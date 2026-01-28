initTheme();
document.addEventListener('DOMContentLoaded', () => {
    applyTheme(document.documentElement.getAttribute('data-theme') || DEFAULT_THEME);
});


initSqlJs().then(function(SQL_) {
    SQL = SQL_;
    const createBtn = $('create-db-btn');
    if (createBtn) {
        if (ALLOW_DATABASE_CREATION) {
            createBtn.disabled = false;
            createBtn.classList.remove('hidden');
        } else {
            createBtn.disabled = true;
            createBtn.classList.add('hidden');
        }
    }
    $('load-db-btn').disabled = false;
    showStatus('Not loaded', 'status');
}).catch(function(err) {
    showStatus('Error initializing database: ' + err.message, 'error');
});

$('create-db-btn').addEventListener('click', createNewDatabase);
$('save-db-btn').addEventListener('click', saveDatabase);
$('load-db-btn').addEventListener('click', () => $('load-db-file').click());
$('load-db-file').addEventListener('change', loadDatabase);
const manageUsersBtn = $('manage-users-btn');
if (manageUsersBtn) {
    manageUsersBtn.addEventListener('click', openUserManagementModal);
}
const signOutBtn = $('sign-out-btn');
if (signOutBtn) {
    signOutBtn.addEventListener('click', handleSignOut);
}
const rotateCentralBtn = $('rotate-central-btn');
if (rotateCentralBtn) {
    rotateCentralBtn.addEventListener('click', handleRotateCentralPassword);
}
$('add-patient-btn').addEventListener('click', promptNewPatient);
$('save-all-btn').addEventListener('click', async () => {
    await saveDatabase();
});
$('search-input').addEventListener('input', event => {
    currentSearchTerm = event.target.value.trim().toLowerCase();
    renderPatientTable();
});
const unitFilterBtn = $('unit-filter-btn');
if (unitFilterBtn) {
    unitFilterBtn.addEventListener('click', openRecruitingUnitModal);
}
const unitFilterClose = $('unit-filter-close');
if (unitFilterClose) {
    unitFilterClose.addEventListener('click', closeRecruitingUnitModal);
}
const unitFilterCancel = $('unit-filter-cancel');
if (unitFilterCancel) {
    unitFilterCancel.addEventListener('click', closeRecruitingUnitModal);
}
const unitFilterSave = $('unit-filter-save');
if (unitFilterSave) {
    unitFilterSave.addEventListener('click', saveRecruitingUnitSelection);
}
const unitFilterModal = $('unit-filter-modal');
if (unitFilterModal) {
    unitFilterModal.addEventListener('click', event => {
        if (event.target === unitFilterModal) {
            closeRecruitingUnitModal();
        }
    });
}
$('registration-file').addEventListener('change', importRegistrationExtract);
const registrationFileBtn = $('registration-file-btn');
const registrationFileName = $('registration-file-name');
if (registrationFileBtn) {
    registrationFileBtn.addEventListener('click', () => {
        const input = $('registration-file');
        if (!input || input.disabled) return;
        input.click();
    });
}
if (registrationFileName) {
    registrationFileName.addEventListener('click', () => {
        const input = $('registration-file');
        if (!input || input.disabled) return;
        input.click();
    });
}
$('registration-file').addEventListener('change', (event) => {
    const input = event.target;
    if (!registrationFileName) return;
    const file = input && input.files && input.files[0] ? input.files[0] : null;
    registrationFileName.textContent = file ? file.name : 'No file selected';
});

$('show-all-btn').addEventListener('click', () => setFilter('all'));
$('show-missing-btn').addEventListener('click', () => setFilter('missing'));
$('show-pending-btn').addEventListener('click', () => setFilter('pending'));
$('show-notify-btn').addEventListener('click', () => setFilter('ready_notify'));
$('show-waiting-btn').addEventListener('click', () => setFilter('waiting'));
$('show-final-btn').addEventListener('click', () => setFilter('final_eligibility'));
$('show-ready-btn').addEventListener('click', () => setFilter('ready_randomize'));
$('show-randomized-np-btn').addEventListener('click', () => setFilter('randomized_np'));
$('show-prescribed-btn').addEventListener('click', () => setFilter('randomized_rx'));
$('show-ineligible-btn').addEventListener('click', () => setFilter('ineligible'));
$('show-optedout-btn').addEventListener('click', () => setFilter('opted_out'));
$('show-notes-btn').addEventListener('click', () => setFilter('notes'));
setupSaveLocationControls();
setupUserManagementControls();
window.addEventListener('beforeunload', handleBeforeUnload);

function countDigitsInRange(value, endIndex) {
    if (!value || endIndex <= 0) return 0;
    const limit = Math.min(value.length, endIndex);
    let count = 0;
    for (let i = 0; i < limit; i++) {
        const code = value.charCodeAt(i);
        if (code >= 48 && code <= 57) {
            count += 1;
        }
    }
    return count;
}

function caretIndexFromDigits(value, digitCount) {
    if (!value || digitCount <= 0) return 0;
    let count = 0;
    for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i);
        if (code >= 48 && code <= 57) {
            count += 1;
        }
        if (count >= digitCount) {
            return i + 1;
        }
    }
    return value.length;
}

document.addEventListener('input', event => {
    const target = event.target;
    if (!target || !target.dataset || target.dataset.dateEntry !== 'true') return;
    const rawValue = target.value;
    const formatted = formatDateEntryInput(rawValue);
    if (formatted === rawValue) return;
    const selectionStart = typeof target.selectionStart === 'number' ? target.selectionStart : rawValue.length;
    const selectionEnd = typeof target.selectionEnd === 'number' ? target.selectionEnd : selectionStart;
    const digitsBeforeStart = countDigitsInRange(rawValue, selectionStart);
    const digitsBeforeEnd = countDigitsInRange(rawValue, selectionEnd);
    target.value = formatted;
    if (typeof target.setSelectionRange === 'function') {
        const newStart = caretIndexFromDigits(formatted, digitsBeforeStart);
        const newEnd = caretIndexFromDigits(formatted, digitsBeforeEnd);
        target.setSelectionRange(newStart, newEnd);
    }
});

document.addEventListener('keydown', event => {
    if (event.key !== 'Enter') return;
    const target = event.target;
    if (!target) return;
    const tagName = target.tagName;
    if (tagName === 'TEXTAREA' || tagName === 'SELECT') return;
    const isDateEntry = target.dataset && target.dataset.dateEntry === 'true';
    const isTableInput = target.classList && target.classList.contains('table-input');
    if (!isDateEntry && !isTableInput) return;
    event.preventDefault();
    if (typeof target.blur === 'function') {
        target.blur();
    }
});

window.toggleMasterInclusion = toggleMasterInclusion;
window.toggleMasterExclusion = toggleMasterExclusion;
window.updateCriterion = updateCriterion;
window.updateInlineNotification = updateInlineNotification;
window.updateInlineNotes = updateInlineNotes;
window.updateRandomizedStatus = updateRandomizedStatus;
window.updateHealthCardProvince = updateHealthCardProvince;
window.updateDialysisStartDate = updateDialysisStartDate;
window.toggleTherapyPrescribed = toggleTherapyPrescribed;
window.updateAllocation = updateAllocation;
window.updateStudyId = updateStudyId;
window.assignStudyId = assignStudyId;
window.updateOptOutStatus = updateOptOutStatus;
window.updateOptOutDate = updateOptOutDate;
window.setDialysisDurationConfirmed = setDialysisDurationConfirmed;
window.copyPatientField = copyPatientField;
window.toggleRecordLocked = toggleRecordLocked;
window.handleStudyIdInput = handleStudyIdInput;
window.updatePatientBirthDate = updatePatientBirthDate;
window.updatePatientAge = updatePatientAge;
window.updateDiabetesStatus = updateDiabetesStatus;
window.updatePatientMrn = updatePatientMrn;
window.updatePatientHcn = updatePatientHcn;
window.togglePatientRow = togglePatientRow;
window.deleteManualPatient = deleteManualPatient;
