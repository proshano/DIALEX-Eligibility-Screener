
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
    if (!ensureEligibilityEditablePatient(patient)) return;
    const raw = (value || '').trim();
    if (!raw) {
        if (!patient.birth_date) {
            showRecordWarning('');
            return;
        }
        patient.birth_date = '';
        patient.age = null;
        patient.incl_age = 0;
        clearRandomizationEligibilityConfirmation(patient);
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
    const meetsAgeCriteria = age >= 60 || (age >= 45 && age < 60 && patient.diabetes_known === DIABETES_STATUS.YES);
    patient.incl_age = meetsAgeCriteria ? 1 : 0;
    clearRandomizationEligibilityConfirmation(patient);
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
    if (!ensureEligibilityEditablePatient(patient)) return;
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
        clearRandomizationEligibilityConfirmation(patient);
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
    const meetsAgeCriteria = age >= 60 || (age >= 45 && age < 60 && patient.diabetes_known === DIABETES_STATUS.YES);
    patient.incl_age = meetsAgeCriteria ? 1 : 0;
    clearRandomizationEligibilityConfirmation(patient);
    persistPatient(patient, false);
    refreshPatientRow(patient);
    if (age > DOB_WARNING_YEARS) {
        showRecordWarning(`Check age: ${age} years.`, 'status');
    } else {
        showRecordWarning('');
    }
}

function updateDiabetesStatus(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEligibilityEditablePatient(patient)) return;
    const nextStatus = normalizeDiabetesStatus(value);
    if (patient.diabetes_known === nextStatus) {
        showRecordWarning('');
        return;
    }
    patient.diabetes_known = nextStatus;
    const ageValue = Number.isFinite(patient.age) ? patient.age : null;
    if (Number.isFinite(ageValue)) {
        if (ageValue >= 60) {
            patient.incl_age = 1;
        } else if (ageValue >= 45 && ageValue < 60) {
            patient.incl_age = nextStatus === DIABETES_STATUS.YES ? 1 : 0;
        } else {
            patient.incl_age = 0;
        }
    }
    clearRandomizationEligibilityConfirmation(patient);
    persistPatient(patient, false);
    refreshPatientRow(patient);
    showRecordWarning('');
}

function updatePatientMrn(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEligibilityEditablePatient(patient)) return;
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
    if (!ensureEligibilityEditablePatient(patient)) return;
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
    const formatError = getHealthCardEligibilityError(patient.health_card, patient.health_card_province || '');
    patient.incl_health_card = patient.hasHealthCard && !formatError ? 1 : 0;
    clearRandomizationEligibilityConfirmation(patient);
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
    if (!ensureEligibilityEditablePatient(patient)) return;
    const code = (value || '').trim().toUpperCase();
    if (code && !PROVINCE_LABELS[code]) {
        showRecordWarning('Select a valid province/territory code.', 'error');
        renderPatientTable();
        return;
    }
    patient.health_card_province = code;
    if (patient.health_card) {
        const formatError = getHealthCardEligibilityError(patient.health_card, code);
        if (formatError) {
            patient.incl_health_card = 0;
            showRecordWarning(formatError, 'error');
            clearRandomizationEligibilityConfirmation(patient);
            persistPatient(patient, false);
            refreshPatientRow(patient);
            return;
        }
    }
    patient.incl_health_card = patient.health_card && !getHealthCardEligibilityError(patient.health_card, code) ? 1 : 0;
    clearRandomizationEligibilityConfirmation(patient);
    persistPatient(patient, false);
    refreshPatientRow(patient);
    showRecordWarning('');
}

function updateInlineNotes(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (typeof hasStudyIdIntegrityIssue === 'function' && hasStudyIdIntegrityIssue()) {
        const message = getStudyIdIntegrityBlockingMessage();
        showStatus(message, 'error');
        showRecordWarning(message, 'error');
        return;
    }
    patient.notes = value;
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

async function updateRandomizedStatus(index, value, control = null) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEligibilityEditablePatient(patient)) return;
    const shouldMark = String(value) === '1';
    if (!shouldMark) {
        releaseStudyId(patient.study_id);
        patient.randomized = 0;
        patient.enrollment_status = getNonRandomizedEnrollmentStatus(patient);
        patient.therapy_prescribed = 0;
        patient.allocation = '';
        patient.study_id = '';
        patient.locked_at = '';
        clearRandomizationEligibilityConfirmation(patient);
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
    const hcnEligibilityError = getPatientHealthCardEligibilityError(patient);
    if (hcnEligibilityError) {
        showRecordWarning(hcnEligibilityError, 'error');
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
    const confirmation = await getRandomizationEligibilityConfirmation(patient);
    if (!confirmation.ok) {
        if (control) control.value = '0';
        showRecordWarning('Eligibility confirmation is required before marking randomized.', 'status');
        refreshPatientRow(patient);
        return;
    }
    const previousState = {
        randomization_eligibility_confirmed_at: patient.randomization_eligibility_confirmed_at || '',
        randomization_eligibility_confirmed_by: patient.randomization_eligibility_confirmed_by || '',
        randomized: patient.randomized || 0,
        enrollment_status: patient.enrollment_status || '',
        locked_at: patient.locked_at || '',
        location_at_randomization: patient.location_at_randomization || ''
    };
    applyRandomizationEligibilityConfirmation(patient, confirmation);
    patient.randomized = 1;
    patient.enrollment_status = 'enrolled';
    patient.locked_at = getTorontoNow().toISOString();
    if (!normalizeLocationValue(patient.location_at_randomization)) {
        patient.location_at_randomization = getCanonicalLocationValue(patient.location);
    }
    showRecordWarning('');
    try {
        persistPatient(patient, false, { throwOnError: true, suppressStatus: true });
    } catch (error) {
        console.warn('Unable to save randomized status', error);
        Object.assign(patient, previousState);
        if (control) control.value = '0';
        showStatus('Error saving patient', 'error');
        refreshPatientRow(patient);
        return;
    }
    logRandomizationEligibilityConfirmation(patient, confirmation);
    refreshPatientRow(patient);
}

function updateDialysisStartDate(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEligibilityEditablePatient(patient)) return;
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
        if (isFutureISODateString(normalized)) {
            showRecordWarning('Dialysis start date cannot be in the future.', 'error');
            renderPatientTable();
            return;
        }
        const notification = parseISODate(patient.notification_date);
        const start = parseISODate(normalized);
        if (notification && start && start.getTime() > notification.getTime()) {
            showRecordWarning('Dialysis start date cannot be after notification date.', 'error');
            renderPatientTable();
            return;
        }
        if (patient.birth_date) {
            const birth = parseISODate(patient.birth_date);
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
    clearRandomizationEligibilityConfirmation(patient);
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
    if (!ensureEligibilityEditablePatient(patient)) return;
    if (patient.dialysis_start_date) return;
    patient.dialysis_duration_confirmed = flag ? 1 : 0;
    recalcDialysisInclusion(patient);
    clearRandomizationEligibilityConfirmation(patient);
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function toggleTherapyPrescribed(index, checkbox) {
    const patient = patientsData[index];
    if (!patient || !checkbox) return;
    if (!ensureRandomizedFollowupEditablePatient(patient)) {
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
    if (!ensureRandomizedFollowupEditablePatient(patient)) return;
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
    const formatted = formatStudyIdInput(value || '');
    if (!formatted) {
        releaseStudyId(patient.study_id);
        patient.study_id = '';
        patient.allocation = '';
        patient.therapy_prescribed = 0;
        clearRandomizationEligibilityConfirmation(patient);
        showRecordWarning('');
        persistPatient(patient, false);
        refreshPatientRow(patient);
        return;
    }
    const normalized = normalizeStudyIdValue(formatted);
    if (normalized && normalized === patient.study_id) {
        showRecordWarning('');
        return;
    }
    showRecordWarning('Manual Study ID entry is disabled. Use "Eligible and ready to randomize now" to assign from the Study ID pool.', 'error');
    renderPatientTable();
}

function getTorontoTodayIsoString() {
    const today = getTorontoTodayParts();
    const y = String(today.year).padStart(4, '0');
    const m = String(today.month).padStart(2, '0');
    const d = String(today.day).padStart(2, '0');
    return `${y}-${m}-${d}`;
}

function isRandomizationEligibilityConfirmationCurrent(patient) {
    if (!patient || !patient.randomization_eligibility_confirmed_at) return false;
    return String(patient.randomization_eligibility_confirmed_at).slice(0, 10) === getTorontoTodayIsoString();
}

function buildConfirmationIndicator(label, passed) {
    const className = passed ? 'pass' : 'fail';
    return `<span class="confirmation-indicator ${className}">${escapeHtml(label)}</span>`;
}

function buildConfirmationListItem(label, passed, passLabel = 'Met', failLabel = 'Check') {
    return `
        <li>
            ${buildConfirmationIndicator(passed ? passLabel : failLabel, passed)}
            <span>${escapeHtml(label)}</span>
        </li>
    `;
}

function getOptOutStatusDisplay(status) {
    if (status === OPT_OUT_STATUS.DID_NOT) return 'Did not opt out';
    if (status === OPT_OUT_STATUS.OPTED_OUT) return 'Opted out';
    return 'Pending';
}

function buildConfirmationStatusRow(label, value) {
    return `
        <div class="confirmation-status-row">
            <span class="confirmation-status-label">${escapeHtml(label)}</span>
            <span>${escapeHtml(value || '-')}</span>
        </div>
    `;
}

function buildRandomizationConfirmationSummary(patient) {
    const inclusionHtml = INCLUSION_KEYS
        .map(key => buildConfirmationListItem(labelForKey(key), patient[key] === 1))
        .join('');
    const exclusionHtml = EXCLUSION_KEYS
        .map(key => buildConfirmationListItem(labelForKey(key), patient[key] !== 1, 'Absent', 'Present'))
        .join('');
    const vitalStatusItems = [
        'Open the patient chart in the EMR and confirm no deceased flag or icon is active.',
        'Confirm documented attendance to an in-centre hemodialysis session within the preceding 48 hours.',
        'Review key chart elements for evidence of death, dialysis withdrawal, or transfer to hospice.',
        'Review the EMR messaging or inbox function for communication indicating the patient is deceased.'
    ].map(item => `
        <li>
            ${buildConfirmationIndicator('Review', true)}
            <span>${escapeHtml(item)}</span>
        </li>
    `).join('');
    const notificationDisplay = formatFriendlyDate(patient.notification_date || '') || '-';
    const eligibleDisplay = patient.first_ready_iso ? formatFriendlyDate(patient.first_ready_iso) : '-';
    const optOutDisplay = getOptOutStatusDisplay(patient.opt_out_status || OPT_OUT_STATUS.PENDING);
    const unitDisplay = formatLocationDisplay(getDialysisUnitCanonical(patient)) || '-';

    return `
        <div class="confirmation-grid">
            <div class="confirmation-section full-width">
                <h3>Pre-randomization status</h3>
                ${buildConfirmationStatusRow('Date notified', notificationDisplay)}
                ${buildConfirmationStatusRow('Eligible on', eligibleDisplay)}
                ${buildConfirmationStatusRow('Opt-out status', optOutDisplay)}
                ${buildConfirmationStatusRow('Dialysis unit', unitDisplay)}
            </div>
            <div class="confirmation-section">
                <h3>Inclusion criteria</h3>
                <ul class="confirmation-list">${inclusionHtml}</ul>
            </div>
            <div class="confirmation-section">
                <h3>Exclusion criteria</h3>
                <ul class="confirmation-list">${exclusionHtml}</ul>
            </div>
            <div class="confirmation-section full-width">
                <h3>Vital-status checks</h3>
                <ul class="confirmation-list">${vitalStatusItems}</ul>
            </div>
        </div>
    `;
}

function promptRandomizationEligibilityConfirmation(patient) {
    return new Promise(resolve => {
        const modal = $('randomization-confirmation-modal');
        const titleEl = $('randomization-confirmation-title');
        const messageEl = $('randomization-confirmation-message');
        const form = $('randomization-confirmation-form');
        const summaryEl = $('randomization-confirmation-summary');
        const checkbox = $('randomization-confirmation-checkbox');
        const errorEl = $('randomization-confirmation-error');
        const cancelBtn = $('randomization-confirmation-cancel-btn');
        const submitBtn = $('randomization-confirmation-submit-btn');
        const closeBtn = $('randomization-confirmation-close');

        if (!modal || !titleEl || !messageEl || !form || !summaryEl || !checkbox || !errorEl || !cancelBtn || !submitBtn || !closeBtn) {
            const fallback = window.confirm('Confirm that all eligibility criteria remain satisfied and the vital-status checks have been completed.');
            resolve(fallback);
            return;
        }

        const previouslyFocused = document.activeElement;
        let resolved = false;

        const cleanup = (result) => {
            if (resolved) return;
            resolved = true;
            modal.classList.remove('active');
            form.removeEventListener('submit', onSubmit);
            cancelBtn.removeEventListener('click', onCancel);
            closeBtn.removeEventListener('click', onCancel);
            closeBtn.removeEventListener('keydown', onCloseKeydown);
            modal.removeEventListener('click', onBackdropClick);
            document.removeEventListener('keydown', onKeyDown);
            if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
                try {
                    previouslyFocused.focus({ preventScroll: true });
                } catch (error) {
                    previouslyFocused.focus();
                }
            }
            resolve(result);
        };

        const showError = (message) => {
            errorEl.textContent = message;
            errorEl.classList.remove('hidden');
        };

        const onSubmit = (event) => {
            event.preventDefault();
            errorEl.textContent = '';
            errorEl.classList.add('hidden');
            if (!checkbox.checked) {
                showError('Check the confirmation box before continuing.');
                checkbox.focus();
                return;
            }
            cleanup(true);
        };

        const onCancel = () => cleanup(false);

        const onBackdropClick = (event) => {
            if (event.target === modal) {
                onCancel();
            }
        };

        const onKeyDown = (event) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                onCancel();
            }
        };

        const onCloseKeydown = (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                onCancel();
            }
        };

        const patientLabel = patient.patient_name || getDisplayMrnValue(patient.mrn) || 'this patient';
        titleEl.textContent = 'Confirm eligibility before randomization';
        messageEl.textContent = `Review current eligibility and vital-status checks for ${patientLabel}.`;
        summaryEl.innerHTML = buildRandomizationConfirmationSummary(patient);
        checkbox.checked = false;
        errorEl.textContent = '';
        errorEl.classList.add('hidden');
        submitBtn.textContent = 'Confirm';
        modal.classList.add('active');

        form.addEventListener('submit', onSubmit);
        cancelBtn.addEventListener('click', onCancel);
        closeBtn.addEventListener('click', onCancel);
        closeBtn.addEventListener('keydown', onCloseKeydown);
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onKeyDown);

        requestAnimationFrame(() => checkbox.focus());
    });
}

async function getRandomizationEligibilityConfirmation(patient, options = {}) {
    if (!options.forcePrompt && isRandomizationEligibilityConfirmationCurrent(patient)) {
        return {
            ok: true,
            newlyConfirmed: false,
            timestamp: patient.randomization_eligibility_confirmed_at || '',
            username: patient.randomization_eligibility_confirmed_by || ''
        };
    }
    const confirmed = await promptRandomizationEligibilityConfirmation(patient);
    if (!confirmed) {
        return { ok: false, newlyConfirmed: false, timestamp: '', username: '' };
    }
    return {
        ok: true,
        newlyConfirmed: true,
        timestamp: getSqlTimestamp(),
        username: getCurrentUsername()
    };
}

function applyRandomizationEligibilityConfirmation(patient, confirmation) {
    if (!patient || !confirmation || !confirmation.ok) return;
    patient.randomization_eligibility_confirmed_at = confirmation.timestamp || patient.randomization_eligibility_confirmed_at || '';
    patient.randomization_eligibility_confirmed_by = confirmation.username || patient.randomization_eligibility_confirmed_by || '';
}

function clearRandomizationEligibilityConfirmation(patient) {
    if (!patient) return;
    patient.randomization_eligibility_confirmed_at = '';
    patient.randomization_eligibility_confirmed_by = '';
}

function logRandomizationEligibilityConfirmation(patient, confirmation) {
    if (!patient || !confirmation || !confirmation.newlyConfirmed) return;
    logAuditEvent('randomization_eligibility_confirmed', {
        confirmed_at: confirmation.timestamp || '',
        confirmed_by: confirmation.username || '',
        study_id: patient.study_id || '',
        eligible_on: patient.first_ready_iso || ''
    }, {
        targetType: 'patient',
        targetId: patient.mrn || ''
    });
}

async function assignStudyId(index) {
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
    const hcnEligibilityError = getPatientHealthCardEligibilityError(patient);
    if (hcnEligibilityError) {
        showRecordWarning(hcnEligibilityError, 'error');
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
    const confirmation = await getRandomizationEligibilityConfirmation(patient, { forcePrompt: true });
    if (!confirmation.ok) {
        showRecordWarning('Eligibility confirmation is required before assigning a Study ID.', 'status');
        return;
    }
    const patientToPersist = { ...patient, study_id: available };
    applyRandomizationEligibilityConfirmation(patientToPersist, confirmation);
    if (!normalizeLocationValue(patientToPersist.location_at_randomization)) {
        patientToPersist.location_at_randomization = getCanonicalLocationValue(patientToPersist.location);
    }
    try {
        claimStudyIdAndPersistPatient(patientToPersist, available);
    } catch (error) {
        console.warn('Unable to claim Study ID', error);
        showRecordWarning('Unable to assign Study ID. Try again.', 'error');
        renderPatientTable();
        return;
    }
    Object.assign(patient, patientToPersist);
    logRandomizationEligibilityConfirmation(patient, confirmation);
    showRecordWarning('');
    refreshPatientRow(patient);
}

function claimStudyIdAndPersistPatient(patient, studyId) {
    if (!db) {
        throw new Error('Database not initialized');
    }
    const normalizedStudyId = (studyId || '').trim();
    if (!normalizedStudyId) {
        throw new Error('Missing Study ID');
    }
    let inTransaction = false;
    let deleteStmt = null;
    try {
        db.run('BEGIN');
        inTransaction = true;
        deleteStmt = db.prepare('DELETE FROM study_ids WHERE study_id = ?');
        deleteStmt.run([normalizedStudyId]);
        const rowsDeleted = typeof db.getRowsModified === 'function' ? db.getRowsModified() : 1;
        deleteStmt.free();
        deleteStmt = null;
        if (rowsDeleted < 1) {
            throw new Error('Study ID not available');
        }
        persistPatient(patient, false, { throwOnError: true, suppressStatus: true });
        db.run('COMMIT');
        inTransaction = false;
    } catch (error) {
        if (deleteStmt) {
            try {
                deleteStmt.free();
            } catch (freeError) {
                console.warn('Unable to release Study ID statement', freeError);
            }
        }
        if (inTransaction) {
            try {
                db.run('ROLLBACK');
            } catch (rollbackError) {
                console.warn('Unable to rollback Study ID claim', rollbackError);
            }
        }
        throw error;
    }
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

async function reauthenticateCurrentUser(actionLabel = 'continue') {
    if (!db || !currentUser || !currentUser.username) {
        showStatus('Sign in to continue.', 'error');
        return false;
    }
    const normalized = normalizeUsername(currentUser.username);
    const userRecord = fetchUserByUsername(normalized);
    if (!userRecord || !Number(userRecord.active)) {
        showStatus('Your account is unavailable. Sign in again.', 'error');
        return false;
    }
    const password = await promptPasswordModal({
        title: 'Confirm your credentials',
        message: `Enter your password to ${actionLabel}.`,
        requireConfirmation: false,
        submitLabel: 'Confirm',
        autocomplete: 'current-password'
    });
    if (!password) {
        showStatus('Action canceled.', 'status');
        return false;
    }
    const valid = await verifyPassword(password, userRecord.password_salt, userRecord.password_hash);
    if (!valid) {
        showStatus('Incorrect password.', 'error');
        return false;
    }
    return true;
}

async function toggleRecordLocked(index, checked) {
    const patient = patientsData[index];
    if (!patient) return;
    if (typeof hasStudyIdIntegrityIssue === 'function' && hasStudyIdIntegrityIssue()) {
        const message = getStudyIdIntegrityBlockingMessage();
        showStatus(message, 'error');
        showRecordWarning(message, 'error');
        return;
    }
    if (checked) {
        patient.locked_at = getTorontoNow().toISOString();
        if (patient.randomized) {
            showStatus('Record locked. Allocation and prescribed remain editable after randomization.', 'success');
        } else {
            showStatus('Record locked. Only notes remain editable.', 'success');
        }
    } else {
        if (!isAdminUser()) {
            await promptAcknowledgeModal({
                title: 'Admin access required',
                message: 'Only admin users can unlock records.',
                acknowledgeLabel: 'Acknowledged'
            });
            renderPatientTable();
            return;
        }
        const canUnlock = await reauthenticateCurrentUser('unlock this record');
        if (!canUnlock) {
            renderPatientTable();
            return;
        }
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

function persistPatient(patient, refresh = true, options = {}) {
    const persistOptions = options && typeof options === 'object' ? options : {};
    if (!db) {
        if (persistOptions.throwOnError) {
            throw new Error('Database not initialized');
        }
        return;
    }
    if (typeof hasStudyIdIntegrityIssue === 'function' && hasStudyIdIntegrityIssue()) {
        const message = getStudyIdIntegrityBlockingMessage();
        if (!persistOptions.suppressStatus) {
            showStatus(message, 'error');
            showRecordWarning(message, 'error');
        }
        if (persistOptions.throwOnError) {
            throw new Error(message);
        }
        return;
    }
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
                did_not_opt_out, dialysis_duration_confirmed, study_id,
                randomization_eligibility_confirmed_at, randomization_eligibility_confirmed_by,
                locked_at, diabetes_known, no_exclusions_confirmed,
                entry_source, created_by, updated_by,
                ${INCLUSION_KEYS.concat(EXCLUSION_KEYS).join(', ')},
                created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
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
            patient.randomization_eligibility_confirmed_at || '',
            patient.randomization_eligibility_confirmed_by || '',
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
        if (!persistOptions.suppressStatus) {
            showStatus('Error saving patient', 'error');
        }
        if (persistOptions.throwOnError) {
            throw error;
        }
    }
}

function isTemporaryMrn(value) {
    return typeof value === 'string' && value.startsWith(TEMP_MRN_PREFIX);
}

function isManualPatientRecord(patient) {
    if (!patient) return false;
    if (patient.entry_source) {
        return patient.entry_source === ENTRY_SOURCE_MANUAL;
    }
    return isTemporaryMrn(patient.mrn);
}

function isPristineManualPatientRecord(patient) {
    if (!isManualPatientRecord(patient)) return false;
    return !String(patient.patient_name || '').trim()
        && !Number.isFinite(patient.age)
        && !String(patient.location || '').trim()
        && !String(patient.location_at_notification || '').trim()
        && !String(patient.location_at_randomization || '').trim()
        && !String(patient.health_card || '').trim()
        && !String(patient.health_card_province || '').trim()
        && !String(patient.birth_date || '').trim()
        && !String(patient.dialysis_start_date || '').trim()
        && !patient.dialysis_duration_confirmed
        && !String(patient.notification_date || '').trim()
        && !String(patient.randomization_date || '').trim()
        && !patient.randomized
        && !String(patient.study_id || '').trim()
        && !String(patient.notes || '').trim();
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
        patient_name: '',
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
        randomization_eligibility_confirmed_at: '',
        randomization_eligibility_confirmed_by: '',
        did_not_opt_out: 0,
        dialysis_duration_confirmed: 0,
        locked_at: '',
        diabetes_known: DIABETES_STATUS.UNKNOWN,
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
    if (patient.notification_date) {
        showRecordWarning('Notified records cannot be deleted.', 'error');
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
    if (typeof hasStudyIdIntegrityIssue === 'function' && hasStudyIdIntegrityIssue()) {
        const message = getStudyIdIntegrityBlockingMessage();
        showStatus(message, 'error');
        showRecordWarning(message, 'error');
        return;
    }
    const tempMrn = generateTemporaryMrn();
    const patient = createBlankPatientRecord(tempMrn);
    persistPatient(patient);
    const searchInput = $('search-input');
    if (searchInput) {
        searchInput.value = '';
    }
    currentSearchTerm = '';
    if (typeof setRecruitingUnitExtras === 'function') {
        setRecruitingUnitExtras({
            [UNIT_FILTER_EXTRA_KEYS.INCLUDE_NO_UNIT]: true,
            [UNIT_FILTER_EXTRA_KEYS.INCLUDE_NOT_IN_SCOPE]: recruitingUnitIncludeNotInScope
        }, { persist: false, refresh: false });
    }
    if (typeof setFilter === 'function') {
        setFilter('all');
    } else {
        currentFilter = 'all';
        renderPatientTable();
    }
    showRecordWarning('Blank patient row added. Enter the patient details directly in the table.', 'status');
    showStatus('Blank patient row added', 'success');
    focusPatientRow(tempMrn);
}

function isCsvFile(file) {
    if (!file) return false;
    const name = String(file.name || '').trim();
    const type = String(file.type || '').toLowerCase();
    const hasCsvExtension = /\.csv$/i.test(name);
    if (hasCsvExtension) return true;
    if (!name) {
        return type === 'text/csv' || type === 'application/csv' || type === 'application/vnd.ms-excel';
    }
    return false;
}

function getExistingStudyIdsForImport() {
    const existing = new Set();
    if (!db) return existing;
    let stmt = null;
    try {
        stmt = db.prepare(`
            SELECT study_id FROM study_ids
            UNION
            SELECT study_id FROM patient_assessments
            WHERE TRIM(COALESCE(study_id, '')) <> ''
        `);
        while (stmt.step()) {
            const row = stmt.getAsObject();
            const normalized = normalizeStudyIdValue(row.study_id || '');
            if (normalized) {
                existing.add(normalized);
            }
        }
    } finally {
        if (stmt) stmt.free();
    }
    return existing;
}

function ensureStudyIdImportAllowed() {
    if (!db) {
        showStatus('Create or load a database first.', 'error');
        return false;
    }
    if (!currentUser) {
        showStatus('Sign in to continue.', 'error');
        return false;
    }
    if (!isAdminUser()) {
        showStatus('Only admins can import additional Study IDs.', 'error');
        return false;
    }
    if (!isAutosaveReady()) {
        showStatus('Autosave must be ready before importing. Select a save folder and confirm encryption.', 'error');
        return false;
    }
    if (typeof hasStudyIdIntegrityIssue === 'function' && hasStudyIdIntegrityIssue()) {
        const message = getStudyIdIntegrityBlockingMessage();
        showStatus(message, 'error');
        showRecordWarning(message, 'error');
        return false;
    }
    return true;
}

async function importStudyIdsCsv(event) {
    const input = event && event.target ? event.target : null;
    const file = input && input.files && input.files[0] ? input.files[0] : null;
    if (input) {
        input.value = '';
    }
    if (!file) return;
    if (!ensureStudyIdImportAllowed()) return;
    if (!isCsvFile(file)) {
        showStatus('Study ID import requires a .csv file.', 'error');
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

    let parsed;
    try {
        parsed = parseStudyIdImportCSV(csvText || '');
    } catch (error) {
        console.error(error);
        showStatus('Error parsing CSV: ' + error.message, 'error');
        return;
    }

    const counters = {
        total_rows: parsed.counters.total_rows || 0,
        invalid: parsed.counters.invalid || 0,
        duplicate_in_file: parsed.counters.duplicate_in_file || 0,
        already_existing: 0,
        added: 0
    };
    const filename = file.name || 'study_ids.csv';
    const existing = getExistingStudyIdsForImport();
    let stmt = null;
    let inTransaction = false;
    try {
        const createdAt = getSqlTimestamp();
        stmt = db.prepare('INSERT OR IGNORE INTO study_ids (study_id, created_at) VALUES (?, ?)');
        db.run('BEGIN');
        inTransaction = true;
        (parsed.ids || []).forEach(studyId => {
            if (existing.has(studyId)) {
                counters.already_existing += 1;
                return;
            }
            stmt.run([studyId, createdAt]);
            const changed = typeof db.getRowsModified === 'function' ? db.getRowsModified() : 1;
            if (changed > 0) {
                counters.added += 1;
                existing.add(studyId);
            } else {
                counters.already_existing += 1;
            }
        });
        db.run('COMMIT');
        inTransaction = false;
    } catch (error) {
        console.error('Failed to import Study IDs', error);
        if (inTransaction) {
            try {
                db.run('ROLLBACK');
            } catch (rollbackError) {
                console.warn('Unable to rollback Study ID import', rollbackError);
            }
        }
        showStatus('Unable to import Study IDs from CSV.', 'error');
        return;
    } finally {
        if (stmt) stmt.free();
    }

    if (counters.added > 0) {
        markDatabaseChanged();
        loadRecruitingUnitState();
        renderPatientTable();
        updateFilterCounts();
    }

    logAuditEvent('study_ids_imported', {
        filename,
        total_rows: counters.total_rows,
        invalid: counters.invalid,
        duplicate_in_file: counters.duplicate_in_file,
        already_existing: counters.already_existing,
        added: counters.added
    }, {
        targetType: 'study_id_pool',
        targetId: filename
    });

    const summary = `Added ${counters.added} new Study IDs. Skipped ${counters.already_existing} existing, ${counters.invalid} invalid, ${counters.duplicate_in_file} duplicates in file.`;
    const statusType = counters.added > 0 ? 'success' : 'status';
    showStatus(summary, statusType);
    showToast(summary, statusType);
}

async function importRegistrationExtract(event) {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    if (!db) {
        showStatus('Create or load a database first.', 'error');
        return;
    }
    if (typeof hasStudyIdIntegrityIssue === 'function' && hasStudyIdIntegrityIssue()) {
        const message = getStudyIdIntegrityBlockingMessage();
        showStatus(message, 'error');
        showRecordWarning(message, 'error');
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

function buildScientificHcnImportNote(rawHealthCard = '') {
    const sample = String(rawHealthCard || '').trim();
    if (!sample) {
        return 'HCN import warning: value appears to be scientific notation. Verify the original full HCN from source records.';
    }
    return `HCN import warning: value appears to be scientific notation (${sample}). Verify the original full HCN from source records.`;
}

function formatPercent(part, total) {
    if (!Number.isFinite(total) || total <= 0) return '0.00%';
    const ratio = (part / total) * 100;
    return `${ratio.toFixed(2)}%`;
}

function buildRecruitmentSummaryRows() {
    const notifiedDenominator = patientsData.reduce((count, patient) => {
        if (!patient) return count;
        return patient.notification_date ? count + 1 : count;
    }, 0);
    const today = startOfToday();
    let inOptOutPeriod = 0;
    let optOutPeriodEndedNoStatus = 0;
    let notified = 0;
    let optedOut = 0;
    let ineligibleAfterNotified = 0;
    let waitingToBeRandomized = 0;
    let randomizedNotPrescribed = 0;
    let randomizedAndPrescribed = 0;

    patientsData.forEach(patient => {
        if (!patient) return;
        const hasNotification = Boolean(patient.notification_date);
        if (!hasNotification) return;

        const flags = patient.bucketFlags || computeBucketFlags(patient);
        const optOutStatus = patient.opt_out_status || OPT_OUT_STATUS.PENDING;
        const hasRandomization = Boolean(patient.randomized);
        const isOptedOut = optOutStatus === OPT_OUT_STATUS.OPTED_OUT;
        const isPrescribed = Boolean(patient.therapy_prescribed);
        const notificationDate = parseISODate(patient.notification_date);
        const optOutEndDate = notificationDate ? addDays(notificationDate, NOTIFICATION_BUFFER_DAYS) : null;
        const optOutWindowComplete = Boolean(optOutEndDate && optOutEndDate.getTime() <= today.getTime());

        notified += 1;
        if (hasRandomization) {
            if (isPrescribed) {
                randomizedAndPrescribed += 1;
            } else {
                randomizedNotPrescribed += 1;
            }
            return;
        }
        if (isOptedOut) {
            optedOut += 1;
            return;
        }
        if (flags.ineligible) {
            ineligibleAfterNotified += 1;
            return;
        }
        if (!optOutWindowComplete) {
            inOptOutPeriod += 1;
            return;
        }
        if (optOutStatus === OPT_OUT_STATUS.PENDING) {
            optOutPeriodEndedNoStatus += 1;
            return;
        }
        if (optOutStatus === OPT_OUT_STATUS.DID_NOT) {
            waitingToBeRandomized += 1;
            return;
        }
        optOutPeriodEndedNoStatus += 1;
    });

    return [
        ['Recruitment State', 'Count', 'Percent of notified'],
        ['Notified patients', String(notified), notifiedDenominator > 0 ? '100.00%' : '0.00%'],
        ['In opt-out period', String(inOptOutPeriod), formatPercent(inOptOutPeriod, notifiedDenominator)],
        ['Opt-out period ended, opt-out status not documented', String(optOutPeriodEndedNoStatus), formatPercent(optOutPeriodEndedNoStatus, notifiedDenominator)],
        ['Opted out', String(optedOut), formatPercent(optedOut, notifiedDenominator)],
        ['Did not opt-out, but deemed ineligible for another reason after notification', String(ineligibleAfterNotified), formatPercent(ineligibleAfterNotified, notifiedDenominator)],
        ['Did not opt out, waiting to be randomized', String(waitingToBeRandomized), formatPercent(waitingToBeRandomized, notifiedDenominator)],
        ['Randomized, not yet prescribed', String(randomizedNotPrescribed), formatPercent(randomizedNotPrescribed, notifiedDenominator)],
        ['Randomized and prescribed', String(randomizedAndPrescribed), formatPercent(randomizedAndPrescribed, notifiedDenominator)]
    ];
}

function csvEscape(value) {
    const raw = value === null || value === undefined ? '' : String(value);
    if (/[,"\n\r]/.test(raw)) {
        return `"${raw.replace(/"/g, '""')}"`;
    }
    return raw;
}

function convertRowsToCsv(rows) {
    return rows
        .map(row => row.map(csvEscape).join(','))
        .join('\n');
}

function exportRecruitmentSummaryCsv() {
    if (!db || !currentUser) {
        showStatus('Load and unlock a database first.', 'error');
        return;
    }
    const rows = buildRecruitmentSummaryRows();
    const csv = convertRowsToCsv(rows);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const filename = `dialex-recruitment-summary-${formatTimestampForFilename()}.csv`;
    triggerBrowserDownload(blob, filename);
    showStatus('Recruitment summary exported.', 'success');
}

function ingestRegistrationRows(rows) {
    if (!Array.isArray(rows) || rows.length === 0) {
        showStatus('CSV did not contain any usable patient rows.', 'error');
        return;
    }
    if (!db) return;
    let inTransaction = false;
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
    const scientificNotationHcns = [];
    const missingMrnSeed = getTorontoNowTimestamp();
    let missingMrnCounter = 0;
    const nextMissingMrn = () => {
        let candidate = '';
        do {
            candidate = `${TEMP_MRN_PREFIX}${missingMrnSeed}-${missingMrnCounter++}`;
        } while (seenMrns.has(candidate));
        return candidate;
    };
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
    try {
        db.run('BEGIN');
        inTransaction = true;
        rows.forEach(original => {
            if (!original) return;
        const rawMrn = (original[MRN_HEADER] || '').toString().trim();
        const patientName = getPatientNameFromRow(original);
        const rawLocationCode = getField(original, [LOCATION_HEADER]) || '';
        const locationCode = getLocationCodeFromValue(rawLocationCode);
        const locationName = getLocationNameFromCode(locationCode);
        const locationDisplay = locationCode && locationName
            ? `${locationCode}: ${locationName}`
            : (rawLocationCode || '');
        const healthCard = String(getField(original, [LAST_HCN_HEADER, 'Latest Known HCN', HCN_HEADER]) || '').trim();
        const healthCardProvince = getField(original, [HCN_PROVINCE_HEADER]) || '';
        const scientificNotationHcn = isScientificNotationNumericText(healthCard);
        const normalizedHealthCard = scientificNotationHcn ? '' : normalizeHealthCardValue(healthCard);
        let duplicateReason = '';
        if (rawMrn && seenMrns.has(rawMrn)) {
            duplicateReason = 'MRN';
        } else if (normalizedHealthCard && seenHcns.has(normalizedHealthCard)) {
            duplicateReason = 'Health card';
        }
        if (duplicateReason) {
            duplicates.push({ mrn: rawMrn, healthCard, reason: duplicateReason });
            return;
        }
        const mrn = rawMrn || nextMissingMrn();
        const province = healthCardProvince;
        const hcnValidationError = normalizedHealthCard
            ? getHealthCardEligibilityError(normalizedHealthCard, province || '')
            : '';
        const hcnImportNote = scientificNotationHcn ? buildScientificHcnImportNote(healthCard) : '';
        if (scientificNotationHcn) {
            scientificNotationHcns.push({ mrn, healthCard });
        }
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
        const diabetesStatus = resolveDiabetesStatus(diabetesType1, diabetesType2);
        const hasDiabetes = diabetesStatus === DIABETES_STATUS.YES;
        const inclusionValues = [
            computeInclusionAge(age, hasDiabetes),
            startIsoValid ? meetsDialysisDays(startIsoValid) : 0,
            hasValidModality ? 1 : 0,
            (normalizedHealthCard && !hcnValidationError) ? 1 : 0
        ];
        const exclusionValues = EXCLUSION_KEYS.map(() => 0);
        const values = [
            mrn,                               // mrn
            patientName,                       // patient_name
            age,                               // age
            locationDisplay,                   // location
            '',                                // location_at_notification
            '',                                // location_at_randomization
            normalizedHealthCard,              // health_card
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
            hcnImportNote,                     // notes
            'pending',                         // enrollment_status
            0,                                 // therapy_prescribed
            0,                                 // did_not_opt_out
            0,                                 // dialysis_duration_confirmed
            '',                                // locked_at
            diabetesStatus,                    // diabetes_known
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
        db.run('COMMIT');
        inTransaction = false;
    } catch (error) {
        console.error('Failed to import patients', error);
        if (inTransaction) {
            try {
                db.run('ROLLBACK');
            } catch (rollbackError) {
                console.warn('Unable to rollback patient import', rollbackError);
            }
        }
        showStatus('Unable to import patients from CSV.', 'error');
        return;
    } finally {
        if (stmt) stmt.free();
    }
    refreshPatientData();
    if (typeof setFilter === 'function') {
        setFilter('pending');
    } else {
        currentFilter = 'pending';
    }
    markDatabaseChanged();
    let statusMessage;
    if (imported) {
        statusMessage = `Imported ${imported} patient${imported === 1 ? '' : 's'} from CSV.`;
    } else {
        statusMessage = 'No new patients imported.';
    }
    if (scientificNotationHcns.length) {
        statusMessage += ` Flagged ${scientificNotationHcns.length} HCN value${scientificNotationHcns.length === 1 ? '' : 's'} that appear to be scientific notation.`;
    }
    const warningMessages = [];
    if (duplicates.length) {
        statusMessage += ` Skipped ${duplicates.length} duplicate${duplicates.length === 1 ? '' : 's'}.`;
        const sample = duplicates.slice(0, 5).map(entry => {
            if (entry.reason === 'MRN') {
                return `MRN ${entry.mrn}`;
            }
            return entry.healthCard ? `HCN ${entry.healthCard}` : `MRN ${entry.mrn}`;
        });
        const more = duplicates.length > sample.length ? '…' : '';
        warningMessages.push(`Skipped duplicate imports (${duplicates.length}): ${sample.join(', ')}${more}`);
    }
    if (scientificNotationHcns.length) {
        const samples = scientificNotationHcns.slice(0, 5).map(entry => {
            const mrnLabel = entry.mrn ? `MRN ${entry.mrn}` : 'MRN missing';
            const hcnLabel = entry.healthCard ? ` (${entry.healthCard})` : '';
            return `${mrnLabel}${hcnLabel}`;
        });
        const more = scientificNotationHcns.length > samples.length ? '…' : '';
        warningMessages.push(`Flagged HCN values in scientific notation (${scientificNotationHcns.length}): ${samples.join(', ')}${more}`);
    }
    if (warningMessages.length) {
        showRecordWarning(warningMessages.join(' '), 'error');
    } else {
        showRecordWarning('');
    }
    logAuditEvent('patients_imported', {
        imported,
        duplicates: duplicates.length,
        scientific_hcn_flagged: scientificNotationHcns.length
    }, {
        targetType: 'patient',
        targetId: ''
    });
    showStatus(statusMessage, imported ? 'success' : 'status');
}
