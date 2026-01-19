
function isHealthCardValid(patient) {
    if (!patient) return false;
    const province = patient.health_card_province || inferProvinceFromHealthCard(patient.health_card || '');
    const error = validateHealthCardFormat(patient.health_card || '', province || '');
    return !error;
}

function computeBucketFlags(patient = {}) {
    const flags = {
        missing: false,
        pending: false,
        ready_notify: false,
        waiting: false,
        final_eligibility: false,
        ready_randomize: false,
        randomized_np: false,
        randomized_rx: false,
        ineligible: false,
        opted_out: false,
        notes: false,
        primary: 'all'
    };
    if (!patient) {
        return flags;
    }
    const hasHealthCard = Boolean((patient.health_card || '').trim());
    const hcnProvince = (patient.health_card_province || '').trim();
    const requiresDialysisUnit = patient.incl_incentre_hd === 1;
    const locationValue = requiresDialysisUnit ? getDialysisUnitCanonical(patient) : '';
    const hasDialysisUnit = requiresDialysisUnit && Boolean(normalizeLocationValue(locationValue));
    const hasDialysisHistory = Boolean(patient.dialysis_start_date) || Boolean(patient.dialysis_duration_confirmed);
    const missingHcnInfo = !hasHealthCard || !hcnProvince;
    const hcnFormatError = hasHealthCard ? validateHealthCardFormat(patient.health_card, hcnProvince || '') : '';
    flags.missing = !hasHealthCard || !hcnProvince || !!hcnFormatError || (requiresDialysisUnit && !hasDialysisUnit) || !hasDialysisHistory;

    const optOutStatus = patient.opt_out_status || OPT_OUT_STATUS.PENDING;
    const isOptedOutStatus = optOutStatus === OPT_OUT_STATUS.OPTED_OUT;
    flags.opted_out = isOptedOutStatus;
    const hasAnyExclusion = patient.hasAnyExclusion || false;
    flags.ineligible = isOptedOutStatus || hasAnyExclusion || (!patient.inclusionMet && (!flags.missing || missingHcnInfo));

    const today = startOfToday();
    const hasNotification = Boolean(patient.notification_date);
    const notificationDate = parseISODate(patient.notification_date);
    const optOutEndDate = notificationDate ? addDays(notificationDate, NOTIFICATION_BUFFER_DAYS) : null;
    const optOutWindowComplete = Boolean(optOutEndDate && optOutEndDate.getTime() <= today.getTime());
    const firstEligibleDate = patient.first_ready_date || null;
    const eligibleWindowStarted = Boolean(firstEligibleDate && firstEligibleDate.getTime() <= today.getTime());
    const hasRandomization = Boolean(patient.randomized);
    const notMissingOrIneligible = !flags.missing && !flags.ineligible;
    const hasConfirmedNoExclusions = Boolean(patient.no_exclusions_confirmed);
    const meetsEligibility = patient.inclusionMet && !hasAnyExclusion && hasConfirmedNoExclusions;

    if (notMissingOrIneligible) {
        if (!hasNotification) {
            if (patient.inclusionMet && !hasAnyExclusion) {
                if (hasConfirmedNoExclusions) {
                    flags.ready_notify = true;
                } else {
                    flags.pending = true;
                }
            }
        } else if (!hasRandomization && !flags.opted_out) {
            if (!meetsEligibility) {
                flags.pending = true;
            } else if (!optOutWindowComplete) {
                flags.waiting = true;
            } else if (optOutStatus === OPT_OUT_STATUS.DID_NOT && eligibleWindowStarted) {
                flags.ready_randomize = true;
            } else {
                flags.final_eligibility = true;
            }
        }
    }

    flags.randomized_rx = hasRandomization && Boolean(patient.therapy_prescribed);
    flags.randomized_np = hasRandomization && !patient.therapy_prescribed;
    flags.notes = Boolean(patient.notes && patient.notes.trim().length > 0);
    flags.primary = determinePrimaryBucket(flags);
    return flags;
}

function determinePrimaryBucket(flags = {}) {
    for (const key of PRIMARY_BUCKET_ORDER) {
        if (flags[key]) {
            return key;
        }
    }
    return 'all';
}

function renderPatientTable() {
    if (renderScheduled) return;
    renderScheduled = true;
    const schedule = window.requestAnimationFrame || function (cb) { return setTimeout(cb, 0); };
    schedule(() => {
        renderScheduled = false;
        renderPatientTableNow();
    });
}

function isSearchActive() {
    return Boolean(currentSearchTerm && currentSearchTerm.trim());
}

function matchesVisibilityFilter(patient) {
    if (!patient) return false;
    if (isSearchActive()) {
        return matchesSearchTerm(patient);
    }
    return matchesUnitFilter(patient) && matchesActiveFilter(patient);
}

function renderPatientTableNow() {
    const tbody = $('patient-table-body');
    const fragment = document.createDocumentFragment();
    const visible = patientsData
        .filter(matchesVisibilityFilter)
        .sort(comparePatients);

    visible.forEach(patient => {
        fragment.appendChild(buildPatientRow(patient));
    });

    if (visible.length === 0) {
        const empty = document.createElement('tr');
        empty.innerHTML = `<td colspan="4" style="text-align:center; padding:24px; color:var(--muted);">No patients match this view.</td>`;
        fragment.appendChild(empty);
    }

    tbody.replaceChildren(fragment);
}

function renderPatientRow(index) {
    const patient = patientsData[index];
    if (!patient) return;
    const tbody = $('patient-table-body');
    const existing = document.getElementById(`row-${index}`);
    const isVisible = matchesVisibilityFilter(patient);

    if (!isVisible) {
        if (existing) {
            existing.remove();
            const existingDetails = document.getElementById(`row-details-${index}`);
            if (existingDetails) existingDetails.remove();
        }
        if (!tbody.children.length) {
            const empty = document.createElement('tr');
            empty.innerHTML = `<td colspan="4" style="text-align:center; padding:24px; color:var(--muted);">No patients match this view.</td>`;
            tbody.appendChild(empty);
        }
        return;
    }

    if (existing) {
        existing.remove();
        const existingDetails = document.getElementById(`row-details-${index}`);
        if (existingDetails) existingDetails.remove();
    }

    const placeholder = tbody.querySelector('tr:not([data-index])');
    if (placeholder) {
        placeholder.remove();
    }

    insertRowSorted(tbody, buildPatientRow(patient), patient);
}

function insertRowSorted(tbody, row, patient) {
    const siblings = Array.from(tbody.children);
    for (const sibling of siblings) {
        const idx = Number(sibling.dataset.index);
        const other = patientsData[idx];
        if (other && comparePatients(patient, other) < 0) {
            tbody.insertBefore(row, sibling);
            return;
        }
    }
    tbody.appendChild(row);
}

let expandedPatientIndex = null;

function getStatusBadgeHtml(patient) {
    const flags = patient.bucketFlags || computeBucketFlags(patient);
    const primary = flags.primary;
    const statusLabels = {
        missing: 'Missing',
        pending: 'Assess eligibility for notification',
        ready_notify: 'Deliver notification',
        waiting: 'Notified and waiting',
        final_eligibility: 'Assess eligibility for randomization',
        ready_randomize: 'Ready to Randomize',
        randomized_np: 'Randomized (Not Prescribed)',
        randomized_rx: 'Randomized (Prescribed)',
        ineligible: 'Ineligible',
        opted_out: 'Opted Out'
    };
    let label = statusLabels[primary] || 'All';
    const statusClass = `status-${primary.replace(/_/g, '-')}`;

    // Add allocation info for randomized patients
    if ((primary === 'randomized_np' || primary === 'randomized_rx') && patient.allocation) {
        const allocationLabels = {
            'conventional': 'Conventional',
            'elisio_hx': 'Elisio-HX'
        };
        const allocationLabel = allocationLabels[patient.allocation] || patient.allocation;
        label += ` - ${allocationLabel}`;
    }

    return `<div class="status-badge ${statusClass}">${label}</div>`;
}

function togglePatientRow(index) {
    const previous = expandedPatientIndex;
    if (previous !== null) {
        collapsePatientDetailsRow(previous);
    }

    if (previous === index) {
        expandedPatientIndex = null;
        return;
    }

    expandedPatientIndex = index;
    expandPatientDetailsRow(index);
}

// Expand/collapse helpers keep DOM work minimal for large tables.
function collapsePatientDetailsRow(index) {
    if (index == null) return;
    const detailsRow = document.getElementById(`row-details-${index}`);
    if (detailsRow) {
        detailsRow.remove();
    }
    const summaryRow = document.getElementById(`row-${index}`);
    if (summaryRow) {
        summaryRow.querySelectorAll('.expand-indicator').forEach(indicator => indicator.classList.remove('expanded'));
    }
}

function expandPatientDetailsRow(index) {
    const patient = patientsData[index];
    if (!patient) return;
    const summaryRow = document.getElementById(`row-${index}`);
    if (!summaryRow) {
        renderPatientTable();
        return;
    }
    summaryRow.querySelectorAll('.expand-indicator').forEach(indicator => indicator.classList.add('expanded'));
    const existingDetails = document.getElementById(`row-details-${index}`);
    if (existingDetails) {
        existingDetails.remove();
    }
    const detailsRow = buildPatientDetailsRow(patient);
    summaryRow.after(detailsRow);
}

function buildPatientRow(patient) {
    const isExpanded = expandedPatientIndex === patient._index;
    const fragment = document.createDocumentFragment();

    // Always create the summary row
    const summaryRow = buildPatientSummaryRow(patient, isExpanded);
    fragment.appendChild(summaryRow);

    // If expanded, add the details row below it
    if (isExpanded) {
        const detailsRow = buildPatientDetailsRow(patient);
        fragment.appendChild(detailsRow);
    }

    return fragment;
}

function buildPatientSummaryRow(patient, isExpanded) {
    const row = document.createElement('tr');
    row.id = `row-${patient._index}`;
    row.dataset.index = patient._index;
    row.className = `${patient.rowClass} patient-row-collapsed`;
    row.dataset.mrn = patient.mrn || '';

    const isLocked = !!patient.locked_at;
    const ageValue = Number.isFinite(patient.age) ? patient.age : '';
    const birthDateValue = formatEntryDate(patient.birth_date || '');
    const dialysisUnitCanonical = getDialysisUnitCanonical(patient);
    const dialysisUnitOptions = buildLocationOptionsHtml(dialysisUnitCanonical);
    const provinceOptions = buildProvinceOptions(patient.health_card_province || '');
    const statusBadge = getStatusBadgeHtml(patient);
    const expandedClass = isExpanded ? 'expanded' : '';
    const displayMrn = getDisplayMrnValue(patient.mrn);

    row.innerHTML = `
        <td colspan="4">
            <div class="patient-collapsed-summary">
                <div class="expand-indicator ${expandedClass}" onclick="togglePatientRow(${patient._index})">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="9 18 15 12 9 6"></polyline>
                    </svg>
                </div>
                <div class="compact-field compact-name">
                    <label>Name</label>
                    <input type="text" class="table-input" placeholder="Patient name" value="${escapeHtml(patient.patient_name || '')}" ${isLocked ? 'disabled' : ''} onchange="updatePatientName(${patient._index}, this.value)">
                </div>
                <div class="compact-field compact-dob" data-field="birth_date">
                    <label>DOB</label>
                    <input type="text" class="table-input" value="${birthDateValue}" placeholder="DD/MM/YYYY" title="DD/MM/YYYY or YYYY-MM-DD" inputmode="numeric" autocomplete="off" spellcheck="false" data-date-entry="true" ${isLocked ? 'disabled' : ''} onchange="updatePatientBirthDate(${patient._index}, this.value)">
                </div>
                <div class="compact-field compact-age">
                    <label>Age</label>
                    <input type="text" class="table-input" placeholder="Age" value="${ageValue}" readonly aria-readonly="true">
                </div>
                <div class="compact-field compact-mrn">
                    <label>MRN</label>
                    <div class="input-with-copy">
                        <input type="text" class="table-input" placeholder="MRN" value="${escapeHtml(displayMrn)}" ${isLocked ? 'disabled' : ''} onchange="updatePatientMrn(${patient._index}, this.value)">
                        <button class="copy-btn-mini" ${displayMrn ? '' : 'disabled'} onclick="copyPatientField(${patient._index}, 'mrn')">Copy</button>
                    </div>
                </div>
                <div class="compact-field compact-hcn" data-field="health_card">
                    <label>HCN</label>
                    <div class="input-with-copy">
                        <input type="text" class="table-input" placeholder="HCN" value="${escapeHtml(patient.health_card || '')}" ${isLocked ? 'disabled' : ''} onchange="updatePatientHcn(${patient._index}, this.value)">
                        <button class="copy-btn-mini" ${patient.health_card ? '' : 'disabled'} onclick="copyPatientField(${patient._index}, 'health_card')">Copy</button>
                    </div>
                </div>
                <div class="compact-field compact-province" data-field="health_card_province">
                    <label>HCN Province</label>
                    <select class="table-input" ${isLocked ? 'disabled' : ''} onchange="updateHealthCardProvince(${patient._index}, this.value)">
                        ${provinceOptions}
                    </select>
                </div>
                <div class="compact-field compact-dialysis" data-field="dialysis_unit">
                    <label>Dialysis Unit</label>
                    <select class="table-input" ${isLocked ? 'disabled' : ''} onchange="updateDialysisUnit(${patient._index}, this.value)">
                        ${dialysisUnitOptions}
                    </select>
                </div>
                <div class="expand-indicator right ${expandedClass}" onclick="togglePatientRow(${patient._index})">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="9 18 15 12 9 6"></polyline>
                    </svg>
                </div>
                <div class="status-badge-wrap">
                    ${statusBadge}
                </div>
            </div>
        </td>
    `;

    return row;
}

function buildPatientDetailsRow(patient) {
    const row = document.createElement('tr');
    row.id = `row-details-${patient._index}`;
    row.dataset.index = patient._index;
    row.className = `${patient.rowClass} patient-row-expanded patient-expanded-details`;
    row.dataset.mrn = patient.mrn || '';

    const firstEligibleDisplay = patient.first_ready_iso ? formatFriendlyDate(patient.first_ready_iso) : '-';
    const dialysisUnitCanonical = getDialysisUnitCanonical(patient);
    const dialysisUnitOptions = buildLocationOptionsHtml(dialysisUnitCanonical);
    const inclusionLabelClass = patient.inclusionMet ? 'check-success font-medium' : '';
    const noExclusionLabelClass = patient.hasAnyExclusion
        ? 'check-danger font-medium'
        : (patient.no_exclusions_confirmed ? 'check-success font-medium' : 'font-medium');
    const isRandomized = !!patient.randomized;
    const isLocked = !!patient.locked_at;
    const ageValue = Number.isFinite(patient.age) ? patient.age : '';
    const notificationDisplay = formatEntryDate(patient.notification_date || '');
    const notificationFriendly = formatFriendlyDate(patient.notification_date);
    const optOutStatus = patient.opt_out_status || OPT_OUT_STATUS.PENDING;
    const optOutDateDisplay = formatEntryDate(patient.opt_out_date || '');
    const optOutFriendly = formatFriendlyDate(patient.opt_out_date);
    const hasEligibleDate = Boolean(patient.first_ready_iso);
    const eligibleWindowStarted = Boolean(patient.first_ready_date && patient.first_ready_date.getTime() <= startOfToday().getTime());
    const meetsEligibility = patient.inclusionMet && !patient.hasAnyExclusion && patient.no_exclusions_confirmed;
    const optOutSelectEnabled = hasEligibleDate || optOutStatus !== OPT_OUT_STATUS.PENDING || !!optOutDateDisplay;
    const optOutDisabled = isLocked ? 'disabled' : (optOutSelectEnabled ? '' : 'disabled');
    const optOutHelper = hasEligibleDate ? '' : '<div class="status-subtext">Calculate eligible date to enable opt-out status.</div>';
    const optOutDateVisible = optOutStatus === OPT_OUT_STATUS.OPTED_OUT;
    const optOutDateDisabled = isLocked ? 'disabled' : (optOutDateVisible && optOutSelectEnabled ? '' : 'disabled');
    const optOutCopyDisabled = optOutDateDisplay && !optOutDateDisabled ? '' : 'disabled';
    const allocationValue = patient.allocation || '';
    const hasAllocation = allocationValue !== '';
    const studyIdValue = patient.study_id || '';
    const hasStudyId = Boolean(studyIdValue);
    const randomizedSelectValue = isRandomized ? '1' : '0';
    const optOutOptions = [
        { value: OPT_OUT_STATUS.PENDING, label: 'Pending' },
        { value: OPT_OUT_STATUS.DID_NOT, label: 'Did not opt out' },
        { value: OPT_OUT_STATUS.OPTED_OUT, label: 'Opted out' }
    ].map(opt => `<option value="${opt.value}" ${opt.value === optOutStatus ? 'selected' : ''}>${opt.label}</option>`).join('');
    const dialysisStartDisplay = formatEntryDate(patient.dialysis_start_date || '');
    const dialysisStartFriendly = formatFriendlyDate(patient.dialysis_start_date);
    const notifiedCopyButton = `<button class="copy-btn" ${patient.notification_date ? '' : 'disabled'} onclick="copyPatientField(${patient._index}, 'notification_date')">Copy date</button>`;
    const dialysisConfirmControls = patient.dialysis_start_date ? '' : `
        <div class="patient-sub" data-field="dialysis_start_date" style="margin-top:4px;">
            <button class="copy-btn" ${isLocked ? 'disabled' : ''} onclick="setDialysisDurationConfirmed(${patient._index}, ${patient.dialysis_duration_confirmed ? 0 : 1})">
                ${patient.dialysis_duration_confirmed ? 'Clear ≥90-day confirmation' : 'Confirm ≥90 days (date unknown)'}
            </button>
            ${patient.dialysis_duration_confirmed ? '<div class="status-subtext" style="margin-top:2px;">Use when exact start date is unavailable.</div>' : ''}
        </div>
    `;
    const missingReasons = computeMissingEligibilityReasons(patient);
    const missingMessage = missingReasons.length
        ? `<div class="status-subtext" style="color:#ffcc66; font-weight:700; margin-top:10px;">Missing: ${missingReasons.join('; ')}</div>`
        : '';
    let eligibleMessage;
    if (patient.first_ready_iso) {
        eligibleMessage = `<div id="first-eligible-${patient._index}" class="text-sm font-medium" style="color:var(--brand);">${firstEligibleDisplay}</div>`;
    } else {
        const missing = [];
        if (!patient.dialysis_start_date && !patient.dialysis_duration_confirmed) missing.push('dialysis start date or ≥90 days confirmation');
        if (!patient.notification_date) missing.push('notification date');
        const missingText = missing.length ? missing.join(' and ') : 'required dates';
        eligibleMessage = `<div class="status-subtext">Set ${missingText}</div>`;
    }
    const canAssignStudyId = optOutStatus === OPT_OUT_STATUS.DID_NOT && eligibleWindowStarted && meetsEligibility;
    const randomizationAllowed = canAssignStudyId && hasStudyId;
    const randomizationRowVisible = randomizationAllowed || isRandomized;
    const randomizationRowStyle = randomizationRowVisible ? '' : 'display:none;';
    const randomizedDisabled = isLocked ? 'disabled' : (randomizationAllowed ? '' : (isRandomized ? '' : 'disabled'));
    let randomizationHelper = '';
    if (!randomizationRowVisible) {
        if (canAssignStudyId && !hasStudyId) {
            randomizationHelper = '';
        } else if (optOutStatus === OPT_OUT_STATUS.DID_NOT && hasEligibleDate && !eligibleWindowStarted) {
            randomizationHelper = `<div class="status-subtext">Eligible on ${firstEligibleDisplay}. Mark randomized once eligible.</div>`;
        } else {
            randomizationHelper = '<div class="status-subtext">Complete eligibility and opt-out steps to mark randomized.</div>';
        }
    }
    const studyRowVisible = canAssignStudyId || isRandomized || hasStudyId;
    const studyRowStyle = studyRowVisible ? '' : 'display:none;';
    const studyCopyDisabled = studyIdValue ? '' : 'disabled';
    const studyHelper = (!hasStudyId && canAssignStudyId)
        ? '<div class="status-subtext">Assign a Study ID to enable randomization.</div>'
        : '';
    const allocationRowVisible = isRandomized && (hasStudyId || hasAllocation || patient.therapy_prescribed);
    const allocationRowStyle = allocationRowVisible ? '' : 'display:none;';
    const allocationDisabled = isLocked ? 'disabled' : ((isRandomized && hasStudyId) ? '' : 'disabled');
    const therapyLabelClass = patient.therapy_prescribed ? 'check-success font-medium' : '';
    const therapyAllowed = isRandomized && hasStudyId && hasAllocation;
    const therapyDisabled = isLocked ? 'disabled' : (therapyAllowed ? '' : 'disabled');
    let therapyHelperMessage = '';
    if (!isRandomized) {
        therapyHelperMessage = 'Mark randomized first.';
    } else if (!hasStudyId) {
        therapyHelperMessage = 'Assign Study ID before prescribing.';
    } else if (!hasAllocation) {
        therapyHelperMessage = 'Select allocation before prescribing.';
    }
    const therapyHelper = allocationRowVisible && therapyHelperMessage ? `<div class="status-subtext">${therapyHelperMessage}</div>` : '';
    const lockToggleDisabled = '';
    const lockIndicator = patient.locked_at ? `<div class="status-subtext locked-indicator">Locked ${formatDisplayDateTime(patient.locked_at)}</div>` : '';
    const lockHelper = '<div class="status-subtext">Lock prevents editing fields above; notes remain editable.</div>';
    const lockDisplay = lockIndicator || lockHelper;
    const isManualRecord = isManualPatientRecord(patient);
    const deleteDisabled = isLocked ? 'disabled' : '';
    const deleteHelper = isLocked
        ? '<div class="status-subtext">Unlock record to delete.</div>'
        : '<div class="status-subtext">This cannot be undone.</div>';
    const manualDeleteHtml = isManualRecord ? `
        <div class="record-actions">
            <button class="danger small" ${deleteDisabled} onclick="deleteManualPatient(${patient._index})">Delete manual record</button>
            ${deleteHelper}
        </div>
    ` : '';
    row.innerHTML = `
        <td colspan="4" style="padding: 0 !important;">
            <div class="patient-expanded-grid">
                <div>
                    <div class="section-label">Inclusion</div>
                    <div class="checkbox-group">
                    <label class="master-check-label">
                        <input type="checkbox" ${patient.inclusionMet ? 'checked' : ''} ${isLocked ? 'disabled' : ''} onchange="toggleMasterInclusion(${patient._index}, this)">
                        <span class="${inclusionLabelClass}">All inclusion criteria met</span>
                    </label>
                    <div class="inline-criteria-list">
                        ${INCLUSION_KEYS.map(key => renderCheckbox(patient, key, isLocked)).join('')}
                    </div>
                    <div class="date-field" data-field="dialysis_start_date" style="margin-top: 10px;">
                        <div class="date-field-header">
                            <label class="patient-sub">Dialysis start date:</label>
                            <span class="date-display ${dialysisStartFriendly ? 'has-value' : ''}">${dialysisStartFriendly || 'Not set'}</span>
                        </div>
                        <div class="date-input-row">
                            <input type="text" class="table-input inline-date" value="${dialysisStartDisplay}" placeholder="DD/MM/YYYY" title="DD/MM/YYYY or YYYY-MM-DD" inputmode="numeric" autocomplete="off" spellcheck="false" data-date-entry="true" ${isLocked ? 'disabled' : ''} onchange="updateDialysisStartDate(${patient._index}, this.value)">
                        </div>
                    </div>
                    ${dialysisConfirmControls}
                </div>
            </div>
            <div>
                    <div class="section-label">Exclusion</div>
                    <div class="checkbox-group">
                        <label class="master-check-label">
                            <input type="checkbox" ${patient.no_exclusions_confirmed ? 'checked' : ''} ${isLocked ? 'disabled' : ''} onchange="toggleMasterExclusion(${patient._index}, this)">
                            <span class="${noExclusionLabelClass}">No exclusions</span>
                        </label>
                        <div class="inline-criteria-list">
                            ${EXCLUSION_KEYS.map(key => renderCheckbox(patient, key, isLocked)).join('')}
                        </div>
                        ${missingMessage}
                    </div>
                </div>
                <div>
            <div class="section-label">Recruitment</div>
            <div style="display:flex; flex-direction:column; gap:6px;">
                <div class="date-field">
                    <div class="date-field-header">
                        <label class="patient-sub">Date notified:</label>
                        <span class="date-display ${notificationFriendly ? 'has-value' : ''}">${notificationFriendly || 'Not set'}</span>
                    </div>
                    <div class="date-input-row">
                        <input type="text" class="table-input inline-date" value="${notificationDisplay}" placeholder="DD/MM/YYYY" title="DD/MM/YYYY or YYYY-MM-DD" inputmode="numeric" autocomplete="off" spellcheck="false" data-date-entry="true" ${isLocked ? 'disabled' : ''} onchange="updateInlineNotification(${patient._index}, this.value)">
                        ${notifiedCopyButton}
                    </div>
                </div>
                <div id="first-eligible-wrap-${patient._index}">
                    <label class="patient-sub">Eligible on:</label>
                    ${eligibleMessage}
                </div>
                <div>
                    <label class="patient-sub">Opt-out status:</label>
                    <select class="table-input" onchange="updateOptOutStatus(${patient._index}, this.value)" ${optOutDisabled}>
                        ${optOutOptions}
                    </select>
                    ${optOutHelper}
                </div>
                <div style="display:${optOutDateVisible ? 'block' : 'none'};">
                    <div class="date-field">
                        <div class="date-field-header">
                            <label class="patient-sub">Date opted out:</label>
                            <span class="date-display ${optOutFriendly ? 'has-value' : ''}">${optOutFriendly || 'Not set'}</span>
                        </div>
                        <div class="date-input-row">
                            <input type="text" class="table-input inline-date" value="${optOutDateDisplay}" placeholder="DD/MM/YYYY" title="DD/MM/YYYY or YYYY-MM-DD" inputmode="numeric" autocomplete="off" spellcheck="false" data-date-entry="true" ${optOutDateDisabled} onchange="updateOptOutDate(${patient._index}, this.value)">
                            <button class="copy-btn" ${optOutCopyDisabled} onclick="copyPatientField(${patient._index}, 'opt_out_date')">Copy date</button>
                        </div>
                    </div>
                </div>
                <div class="inline-field-row" style="${studyRowStyle}">
                    <label class="patient-sub">Study ID:</label>
                    <span class="date-display ${studyIdValue ? 'has-value' : ''}">${studyIdValue || 'Not assigned'}</span>
                    <button class="copy-btn" ${studyCopyDisabled} onclick="copyPatientField(${patient._index}, 'study_id')">Copy</button>
                    <button class="copy-btn" ${isLocked || hasStudyId || !canAssignStudyId ? 'disabled' : ''} onclick="assignStudyId(${patient._index})">Assign Study ID</button>
                </div>
                ${studyHelper}
                ${randomizationHelper}
                <div class="inline-field-row" style="${randomizationRowStyle}">
                    <label class="patient-sub">Randomized:</label>
                    <select class="table-input inline-select" ${randomizedDisabled} onchange="updateRandomizedStatus(${patient._index}, this.value)">
                        <option value="0" ${randomizedSelectValue === '0' ? 'selected' : ''}>No</option>
                        <option value="1" ${randomizedSelectValue === '1' ? 'selected' : ''}>Yes</option>
                    </select>
                </div>
                <div class="inline-field-row" style="${allocationRowStyle}">
                    <label class="patient-sub">Allocation:</label>
                    <select class="table-input inline-select" ${allocationDisabled} onchange="updateAllocation(${patient._index}, this.value)">
                        <option value="" ${allocationValue === '' ? 'selected' : ''}>Select allocation</option>
                        <option value="conventional" ${allocationValue === 'conventional' ? 'selected' : ''}>Conventional high-flux HD</option>
                        <option value="elisio_hx" ${allocationValue === 'elisio_hx' ? 'selected' : ''}>Elisio-HX Expanded HD</option>
                    </select>
                    <label class="master-check-label" style="margin-left:8px; white-space:nowrap;">
                        <input type="checkbox" ${patient.therapy_prescribed ? 'checked' : ''} ${therapyDisabled} onchange="toggleTherapyPrescribed(${patient._index}, this)">
                        <span class="${therapyLabelClass}">Prescribed</span>
                    </label>
                </div>
                ${therapyHelper}
                <div class="lock-section">
                    <div class="inline-field-row" style="align-items:center; gap:6px;">
                        <span aria-hidden="true">🔒</span>
                        <label class="patient-sub" style="margin:0;">Lock record:</label>
                        <input type="checkbox" ${patient.locked_at ? 'checked' : ''} ${lockToggleDisabled} onchange="toggleRecordLocked(${patient._index}, this.checked)">
                    </div>
                    ${lockDisplay}
                </div>
            </div>
                </div>
                <div>
                    <div class="section-label">Notes</div>
                    <textarea class="table-input" rows="6" style="width:100%; resize:vertical;" placeholder="Notes..." onchange="updateInlineNotes(${patient._index}, this.value)">${patient.notes || ''}</textarea>
                    ${manualDeleteHtml}
                </div>
            </div>
        </td>
    `;

    return row;
}

function refreshPatientRow(patient) {
    if (!patient) return patient;
    const normalized = normalizePatientRow(patient, patient._index);
    patientsData[patient._index] = normalized;
    renderPatientRow(normalized._index);
    updateFilterCounts();
    return normalized;
}

function matchesActiveFilter(patient) {
    if (!patient || currentFilter === 'all') return true;
    const flags = patient.bucketFlags || computeBucketFlags(patient);
    switch (currentFilter) {
        case 'missing': return flags.missing;
        case 'pending': return flags.pending || (flags.missing && !flags.ineligible);
        case 'ready_notify': return flags.ready_notify;
        case 'waiting': return flags.waiting;
        case 'final_eligibility': return flags.final_eligibility;
        case 'ready_randomize': return flags.ready_randomize;
        case 'randomized_np': return flags.randomized_np;
        case 'randomized_rx': return flags.randomized_rx;
        case 'ineligible': return flags.ineligible;
        case 'opted_out': return flags.opted_out;
        case 'notes': return flags.notes;
        default: return true;
    }
}

function matchesSearchTerm(patient) {
    if (!currentSearchTerm) return true;
    const haystack = [
        patient.patient_name,
        getDisplayMrnValue(patient.mrn),
        patient.health_card,
        patient.location,
        patient.location_at_notification,
        patient.location_at_randomization,
        patient.mostRecentLocationDisplay
    ].map(val => (val || '').toLowerCase());
    return currentSearchTerm.split(/\s+/).every(token => {
        if (!token) return true;
        return haystack.some(field => field.includes(token));
    });
}

function comparePatients(a, b) {
    const aLocation = getMostRecentLocationSortValue(a);
    const bLocation = getMostRecentLocationSortValue(b);
    const primary = aLocation.localeCompare(bLocation, undefined, { sensitivity: 'base' });
    if (primary !== 0) return primary;

    const aSecondary = getSortValue(a, currentSortKey);
    const bSecondary = getSortValue(b, currentSortKey);
    const secondary = aSecondary.localeCompare(bSecondary, undefined, { sensitivity: 'base' });
    if (secondary !== 0) return secondary;

    const aName = (a.patient_name || '').toLowerCase();
    const bName = (b.patient_name || '').toLowerCase();
    return aName.localeCompare(bName, undefined, { sensitivity: 'base' });
}

function getSortValue(patient, key) {
    if (key === 'mrn') {
        return getDisplayMrnValue(patient.mrn).toLowerCase();
    }
    if (key === 'date-notified') {
        return sortableDateValue(patient.notification_date);
    }
    if (key === 'date-eligible') {
        return sortableDateValue(patient.first_ready_iso);
    }
    if (key === 'date-randomized') {
        return patient.randomized ? '0' : '1';
    }
    return (patient.patient_name || '').toLowerCase();
}

function sortableDateValue(value) {
    return value && value.trim() ? value : '9999-12-31';
}

function highlightPatientFields(index, fields = []) {
    const fieldList = Array.isArray(fields) ? fields.filter(Boolean) : [];
    if (!fieldList.length) return;
    requestAnimationFrame(() => {
        const summaryRow = document.getElementById(`row-${index}`);
        const detailsRow = document.getElementById(`row-details-${index}`);
        const targets = [];
        const collect = (root) => {
            if (!root) return;
            fieldList.forEach(field => {
                root.querySelectorAll(`[data-field="${field}"]`).forEach(el => targets.push(el));
            });
        };
        collect(summaryRow);
        collect(detailsRow);
        if (!targets.length) return;
        targets.forEach(target => {
            target.classList.remove('field-highlight');
            void target.offsetWidth;
            target.classList.add('field-highlight');
            setTimeout(() => target.classList.remove('field-highlight'), FIELD_HIGHLIGHT_DURATION);
        });
        const focusTarget = targets[0].querySelector('input, select, textarea, button');
        if (focusTarget && !focusTarget.disabled) {
            focusTarget.focus();
        }
    });
}

function highlightInclusionSource(index, key) {
    highlightPatientFields(index, INCLUSION_FIELD_MAP[key] || []);
}

function renderCheckbox(patient, key, locked = false) {
    const isChecked = patient[key] === 1 ? 'checked' : '';
    const disabled = locked ? 'disabled' : '';
    return `
        <div class="checkbox-item">
            <input type="checkbox" ${isChecked} ${disabled} onchange="updateCriterion(${patient._index}, '${key}', this.checked)">
            <label>${labelForKey(key)}</label>
        </div>
    `;
}

function labelForKey(key) {
    const labels = {
        incl_age: 'Age ≥60 or 45-59 with history of diabetes',
        incl_dialysis_90d: '≥90 days of dialysis at randomization',
        incl_incentre_hd: 'Receiving in-centre HD',
        incl_health_card: 'Valid provincial/territorial health card number',
        excl_hd_less3: 'Prescribed HD less than 3 times per week',
        excl_intolerance: 'Known/anticipated intolerance to Nipro Elisio HX',
        excl_hdf_planned: 'Planned hemodiafiltration',
        excl_nocturnal: 'Planned nocturnal HD',
        excl_discontinue: 'Expected to stop in-centre HD within 3 months',
        excl_nonadherence: 'Anticipated severe non-adherence',
        excl_preference: 'Overriding clinical preference for expanded HD',
        excl_other_medical: 'Other medical / psychosocial / logistical reason',
        excl_other_trial: 'Enrolled in conflicting clinical trial',
        excl_previous: 'Previously enrolled in DIALEX'
    };
    return labels[key] || key;
}

function toggleMasterInclusion(index, checkbox) {
    const patient = patientsData[index];
    if (!patient || !checkbox) return;
    if (!ensureEditablePatient(patient)) return;
    if (checkbox.checked) {
        const allMet = INCLUSION_KEYS.every(key => patient[key] === 1);
        if (!allMet) {
            checkbox.checked = false;
            showRecordWarning('Check each inclusion criterion below before marking them all as met.', 'error');
        }
        showRecordWarning('');
        return;
    }
    // Prevent unchecking - user must uncheck individual criteria instead
    checkbox.checked = true;
    showRecordWarning('Inclusion criteria are calculated from DOB, dialysis dates, dialysis unit, and health card info. Update those fields to change inclusion.', 'error');
    highlightPatientFields(patient._index, INCLUSION_FIELD_LIST);
}

function toggleMasterExclusion(index, checkbox) {
    const patient = patientsData[index];
    if (!patient || !checkbox) return;
    if (!ensureEditablePatient(patient)) {
        checkbox.checked = !!patient.no_exclusions_confirmed;
        return;
    }
    if (checkbox.checked) {
        const hasExclusions = EXCLUSION_KEYS.some(key => patient[key] === 1);
        if (hasExclusions) {
            checkbox.checked = false;
            showRecordWarning('Clear individual exclusions below before marking "No exclusions".', 'error');
            return;
        }
        patient.no_exclusions_confirmed = 1;
    } else {
        patient.no_exclusions_confirmed = 0;
    }
    persistPatient(patient, false);
    refreshPatientRow(patient);
    showRecordWarning('');
}

function updateCriterion(index, key, checked) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    if (INCLUSION_KEYS.includes(key)) {
        const message = INCLUSION_FIELD_MESSAGES[key] || 'Inclusion criteria are calculated from source fields.';
        showRecordWarning(message, 'error');
        refreshPatientRow(patient);
        highlightInclusionSource(patient._index, key);
        return;
    }
    patient[key] = checked ? 1 : 0;
    if (key === 'incl_health_card') {
        if (!patient.health_card || !patient.health_card.trim()) {
            patient[key] = 0;
            showRecordWarning('Enter a health card number before marking it as valid.', 'error');
            persistPatient(patient, false);
            refreshPatientRow(patient);
            return;
        }
        const province = patient.health_card_province || inferProvinceFromHealthCard(patient.health_card || '');
        const formatError = validateHealthCardFormat(patient.health_card, province || '');
        if (formatError) {
            patient[key] = 0;
            showRecordWarning(formatError, 'error');
            persistPatient(patient, false);
            refreshPatientRow(patient);
            return;
        }
    }
    if (key === 'incl_age') {
        const ageValue = typeof patient.age === 'number' ? patient.age : Number(patient.age);
        if (Number.isFinite(ageValue) && ageValue >= 45 && ageValue < 60) {
            patient.diabetes_known = 1;
        }
    }
    if (EXCLUSION_KEYS.includes(key) && checked) {
        patient.no_exclusions_confirmed = 0;
    }
    persistPatient(patient, false);
    refreshPatientRow(patient);
    showRecordWarning('');
}

function updateInlineNotification(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const newDate = (value || '').trim();
    if (!newDate) {
        patient.notification_date = '';
    } else {
        if (!patient.no_exclusions_confirmed) {
            showRecordWarning('Confirm "No exclusions" before recording a notification date.', 'error');
            renderPatientTable();
            return;
        }
        const normalized = normalizeISODateString(newDate);
            if (!normalized) {
        showRecordWarning('Enter notification date as DD/MM/YYYY.', 'error');
            renderPatientTable();
            return;
        }
        if (isFutureISODateString(normalized)) {
            showRecordWarning('Notification date cannot be in the future.', 'error');
            renderPatientTable();
            return;
        }
        patient.notification_date = normalized;
    }
    if (!patient.notification_date) {
        patient.opt_out_status = OPT_OUT_STATUS.PENDING;
        patient.opt_out_date = '';
        patient.did_not_opt_out = 0;
        patient.randomization_date = '';
        patient.randomized = 0;
        patient.allocation = '';
        releaseStudyId(patient.study_id);
        patient.study_id = '';
        patient.therapy_prescribed = 0;
        patient.enrollment_status = (patient.noExclusions && patient.inclusionMet && patient.no_exclusions_confirmed && patient.hasHealthCard) ? 'eligible' : 'pending';
    }
    showRecordWarning('');
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function updateOptOutStatus(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    if (!patient.notification_date) {
        showRecordWarning('Set a notification date before updating opt-out status.', 'error');
        renderPatientTable();
        return;
    }
    const normalized = normalizeOptOutStatus(value);
    const wantsPending = normalized === OPT_OUT_STATUS.PENDING;
    const firstEligible = computeFirstEligibleDate(patient);
    if (!firstEligible && !wantsPending) {
        showRecordWarning('Calculate the eligible date before updating opt-out status.', 'error');
        renderPatientTable();
        return;
    }
    patient.opt_out_status = normalized;
    patient.did_not_opt_out = normalized === OPT_OUT_STATUS.DID_NOT ? 1 : 0;
    if (normalized !== OPT_OUT_STATUS.OPTED_OUT) {
        patient.opt_out_date = '';
    }
    if (normalized !== OPT_OUT_STATUS.DID_NOT) {
        patient.randomization_date = '';
        patient.randomized = 0;
        patient.allocation = '';
        releaseStudyId(patient.study_id);
        patient.study_id = '';
        patient.therapy_prescribed = 0;
        patient.enrollment_status = (patient.noExclusions && patient.inclusionMet && patient.no_exclusions_confirmed && patient.hasHealthCard) ? 'eligible' : 'pending';
    }
    showRecordWarning('');
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function updateOptOutDate(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    if (!patient.notification_date) {
        showRecordWarning('Set a notification date before recording opt-out date.', 'error');
        renderPatientTable();
        return;
    }
    if (patient.opt_out_status !== OPT_OUT_STATUS.OPTED_OUT) {
        patient.opt_out_status = OPT_OUT_STATUS.OPTED_OUT;
    }
    const dateVal = (value || '').trim();
    if (!dateVal) {
        patient.opt_out_date = '';
        persistPatient(patient, false);
        refreshPatientRow(patient);
        return;
    }
    const normalized = normalizeISODateString(dateVal);
    if (!normalized) {
        showRecordWarning('Enter opt-out date as DD/MM/YYYY.', 'error');
        renderPatientTable();
        return;
    }
    const notification = parseISODate(patient.notification_date);
    const optOutDate = parseISODate(normalized);
    if (notification && optOutDate && optOutDate.getTime() < notification.getTime()) {
        showRecordWarning('Opt-out date cannot be before notification date.', 'error');
        renderPatientTable();
        return;
    }
    patient.opt_out_status = OPT_OUT_STATUS.OPTED_OUT;
    patient.did_not_opt_out = 0;
    patient.opt_out_date = normalized;
    patient.randomization_date = '';
    patient.randomized = 0;
    patient.allocation = '';
    releaseStudyId(patient.study_id);
    patient.study_id = '';
    patient.therapy_prescribed = 0;
    patient.enrollment_status = (patient.noExclusions && patient.inclusionMet && patient.no_exclusions_confirmed && patient.hasHealthCard) ? 'eligible' : 'pending';
    showRecordWarning('');
    persistPatient(patient, false);
    refreshPatientRow(patient);
}

function updateDialysisUnit(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    if (!ensureEditablePatient(patient)) return;
    const canonical = getCanonicalLocationValue(value);
    if (value && value.trim() && !canonical) {
        showRecordWarning('Select a dialysis unit from the list.', 'error');
        renderPatientTable();
        return;
    }
    const studySite = extractStudySite(patient.study_id);
    const locationCode = getLocationCodeFromValue(canonical);
    if (studySite && locationCode && studySite !== locationCode) {
        const siteName = getLocationNameFromCode(studySite) || `site ${studySite}`;
        showRecordWarning(`Study ID site code ${studySite} corresponds to ${siteName}. Check the Study ID or update the dialysis unit at randomization.`, 'error');
        renderPatientTable();
        return;
    }
    showRecordWarning('');
    patient.location_at_randomization = canonical;
    patient.incl_incentre_hd = canonical ? 1 : 0;
    persistPatient(patient, false);
    refreshPatientRow(patient);
}
