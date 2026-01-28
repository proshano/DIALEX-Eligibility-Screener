
function getEditBlockingMessage() {
    if (!db) {
        return 'Load a database to enable patient data.';
    }
    if (!currentUser) {
        return 'Sign in to enable patient data.';
    }
    return getAutosaveBlockingMessage();
}

function getAutosaveBlockingMessage() {
    if (!supportsDirectoryPicker) {
        return 'Continuous data saving requires Google Chrome or Microsoft Edge.';
    }
    if (!saveDirectoryHandle) {
        return 'Select a save folder to enable continuous data saving and editing.';
    }
    if (!saveDirectoryReady) {
        return 'Save folder access is required. Click "Set save folder".';
    }
    if (!isAutosaveEncryptionReady()) {
        return 'This database is not in multi-user encryption mode. Load an updated database or contact your admin.';
    }
    return '';
}

function formatTimestampForFilename(date = getTorontoNow()) {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    const hh = String(date.getHours()).padStart(2, '0');
    const mm = String(date.getMinutes()).padStart(2, '0');
    const ss = String(date.getSeconds()).padStart(2, '0');
    return `${y}-${m}-${d}-${hh}-${mm}-${ss}`;
}

function sanitizeBackupLabel(value) {
    const raw = (value || '').toString().trim();
    const cleaned = raw.replace(/[^A-Za-z0-9 _-]+/g, '');
    const collapsed = cleaned.replace(/\s+/g, '-').replace(/-+/g, '-');
    return collapsed.replace(/^[-_]+|[-_]+$/g, '').slice(0, IMPORT_BACKUP_NAME_MAX);
}

function buildImportBackupFilename(label) {
    const safeLabel = sanitizeBackupLabel(label);
    const timestamp = formatTimestampForFilename();
    return `${IMPORT_BACKUP_PREFIX}${safeLabel}-${timestamp}${IMPORT_BACKUP_EXTENSION}`;
}

function isImportBackupFilename(name) {
    return Boolean(name && name.toLowerCase().startsWith(IMPORT_BACKUP_PREFIX));
}

function isAutosaveReady() {
    return Boolean(db && currentUser && saveDirectoryReady && isAutosaveEncryptionReady());
}

function setDatabaseClean() {
    dbChanged = false;
    lastSavedChangeCounter = dbChangeCounter;
}

function resetAutosaveTracking() {
    dbChanged = false;
    dbChangeCounter = 0;
    lastSavedChangeCounter = 0;
    autosaveQueued = false;
    autosaveInProgress = false;
    manualSaveInProgress = false;
    autosaveToggle = false;
    if (autosaveTimer) {
        clearTimeout(autosaveTimer);
        autosaveTimer = null;
    }
}

function markDatabaseChanged() {
    if (!db) return;
    dbChanged = true;
    dbChangeCounter += 1;
    queueAutosave();
}

function queueAutosave() {
    if (!db || !dbChanged) return;
    if (!isAutosaveReady()) return;
    if (manualSaveInProgress || autosaveInProgress) {
        autosaveQueued = true;
        return;
    }
    if (autosaveTimer) {
        clearTimeout(autosaveTimer);
    }
    autosaveTimer = setTimeout(() => {
        autosaveTimer = null;
        runAutosave();
    }, AUTOSAVE_DEBOUNCE_MS);
}

function getNextAutosaveTarget() {
    autosaveToggle = !autosaveToggle;
    const slot = autosaveToggle ? 'a' : 'b';
    const prefix = slot === 'a' ? AUTOSAVE_PREFIX_A : AUTOSAVE_PREFIX_B;
    const filename = `${prefix}${formatTimestampForFilename()}${AUTOSAVE_EXTENSION}`;
    return { filename, slot };
}

function createAutosaveError(message, code) {
    const error = new Error(message);
    error.code = code;
    return error;
}

async function buildAutosaveBlob() {
    if (!db) {
        throw createAutosaveError('No database loaded for autosave.', 'no_db');
    }
    if (!isAutosaveEncryptionReady()) {
        throw createAutosaveError('Autosave requires multi-user encryption.', 'encryption');
    }
    const sqlData = db.export();
    const encryptedData = await encryptDatabaseV2(sqlData, encryptionState);
    return new Blob([encryptedData], { type: 'application/octet-stream' });
}

async function saveAutosaveBlob(blob, target) {
    const filename = target && target.filename ? target.filename : '';
    const slot = target && target.slot ? target.slot : '';
    if (!filename) {
        throw createAutosaveError('Autosave filename is missing.', 'filename_missing');
    }
    if (!saveDirectoryHandle) {
        throw createAutosaveError('No save folder selected for autosave.', 'no_folder');
    }
    const allowed = await ensureDirectoryPermission(saveDirectoryHandle, { request: false });
    if (!allowed) {
        throw createAutosaveError('Save folder permission missing.', 'no_permission');
    }
    try {
        const fileHandle = await saveDirectoryHandle.getFileHandle(filename, { create: true });
        await writeBlobToHandle(fileHandle, blob);
        if (slot) {
            await cleanupAutosaveFilesForSlot(slot, filename);
        }
        return true;
    } catch (error) {
        const wrapped = createAutosaveError('Unable to write autosave file.', 'write_failed');
        wrapped.cause = error;
        throw wrapped;
    }
}

async function saveBackupBlob(blob, filename) {
    if (!saveDirectoryHandle) {
        throw createAutosaveError('No save folder selected for backup.', 'no_folder');
    }
    const allowed = await ensureDirectoryPermission(saveDirectoryHandle);
    if (!allowed) {
        throw createAutosaveError('Save folder permission missing.', 'no_permission');
    }
    try {
        const fileHandle = await saveDirectoryHandle.getFileHandle(filename, { create: true });
        await writeBlobToHandle(fileHandle, blob);
        return true;
    } catch (error) {
        const wrapped = createAutosaveError('Unable to write backup file.', 'write_failed');
        wrapped.cause = error;
        throw wrapped;
    }
}

async function cleanupAutosaveFilesForSlot(slot, keepName) {
    if (!saveDirectoryHandle) return;
    if (typeof saveDirectoryHandle.entries !== 'function' || typeof saveDirectoryHandle.removeEntry !== 'function') return;
    const prefix = slot === 'a' ? AUTOSAVE_PREFIX_A : AUTOSAVE_PREFIX_B;
    const legacyName = slot === 'a' ? AUTOSAVE_LEGACY_FILE_A : AUTOSAVE_LEGACY_FILE_B;
    try {
        for await (const [name, handle] of saveDirectoryHandle.entries()) {
            if (!handle || handle.kind !== 'file') continue;
            if (name === keepName) continue;
            if (name === legacyName || name.startsWith(prefix)) {
                await saveDirectoryHandle.removeEntry(name);
            }
        }
    } catch (error) {
        console.warn('Unable to clean up autosave files', error);
    }
}

async function createImportBackup(label) {
    if (!db) {
        showStatus('Create or load a database first.', 'error');
        return null;
    }
    if (!isAutosaveReady()) {
        showStatus('Continuous saving must be ready before importing.', 'error');
        return null;
    }
    const sanitizedLabel = sanitizeBackupLabel(label);
    if (!sanitizedLabel) {
        showStatus('Backup file name is required before importing.', 'error');
        return null;
    }
    if (autosaveInProgress) {
        showStatus('Data saving in progress. Please wait...', 'status');
        await waitForAutosaveToFinish();
    }
    manualSaveInProgress = true;
    try {
        const filename = buildImportBackupFilename(sanitizedLabel);
        showStatus(`Saving import backup "${filename}"...`, 'status');
        const blob = await buildAutosaveBlob();
        await saveBackupBlob(blob, filename);
        logAuditEvent('import_backup_created', { filename }, {
            targetType: 'backup',
            targetId: filename
        });
        showStatus(`Import backup saved as "${filename}".`, 'success');
        return filename;
    } catch (error) {
        console.error('Import backup failed', error);
        showStatus('Unable to save import backup: ' + (error && error.message ? error.message : error), 'error');
        return null;
    } finally {
        manualSaveInProgress = false;
        if (dbChanged) {
            queueAutosave();
        }
    }
}

async function handleAutosaveFailure(error) {
    console.error('Data saving failed', error);
    if (error && (error.code === 'no_folder' || error.code === 'no_permission' || error.code === 'write_failed')) {
        saveDirectoryReady = false;
        saveDirectoryHandle = null;
        await clearStoredSaveDirectoryHandle();
        updateSaveFolderStatus();
        updateAppAccessState();
        showStatus('Continuous data saving failed. Select a save folder to continue.', 'error');
        return;
    }
    if (error && error.code === 'encryption') {
        updateAppAccessState();
        showStatus('Continuous data saving requires multi-user encryption. Load an updated database.', 'error');
        return;
    }
    showStatus('Continuous data saving failed: ' + (error && error.message ? error.message : error), 'error');
}

async function runAutosave() {
    if (!isAutosaveReady() || !dbChanged) return;
    if (autosaveInProgress || manualSaveInProgress) {
        autosaveQueued = true;
        return;
    }
    autosaveInProgress = true;
    const changeSnapshot = dbChangeCounter;
    try {
        const blob = await buildAutosaveBlob();
        const target = getNextAutosaveTarget();
        await saveAutosaveBlob(blob, target);
        if (dbChangeCounter === changeSnapshot) {
            setDatabaseClean();
        }
    } catch (error) {
        await handleAutosaveFailure(error);
    } finally {
        autosaveInProgress = false;
        if (autosaveQueued && dbChanged) {
            autosaveQueued = false;
            queueAutosave();
        } else {
            autosaveQueued = false;
        }
    }
}

async function waitForAutosaveToFinish() {
    while (autosaveInProgress) {
        await new Promise(resolve => setTimeout(resolve, 100));
    }
}


function promptPasswordModal(options = {}) {
    return new Promise(resolve => {
        const modal = $('password-modal');
        const titleEl = $('password-modal-title');
        const messageEl = $('password-modal-message');
        const form = $('password-form');
        const passwordInput = $('password-input');
        const confirmGroup = $('password-confirm-group');
        const confirmInput = $('password-confirm-input');
        const errorEl = $('password-error');
        const cancelBtn = $('password-cancel-btn');
        const submitBtn = $('password-submit-btn');
        const closeBtn = $('password-modal-close');
        const requireConfirmation = Boolean(options.requireConfirmation);
        const validate = typeof options.validate === 'function' ? options.validate : null;
        const minLength = Number.isFinite(options.minLength) ? options.minLength : 0;
        const minLengthMessage = options.minLengthMessage
            || (minLength ? `Passwords must be at least ${minLength} characters.` : '');
        const submitLabel = options.submitLabel || (requireConfirmation ? 'Save' : 'Continue');
        const autocompleteValue = options.autocomplete || (requireConfirmation ? 'new-password' : 'current-password');
        const previouslyFocused = document.activeElement;
        let resolved = false;

        titleEl.textContent = options.title || (requireConfirmation ? 'Set a password' : 'Enter password');
        const messageText = options.message == null ? '' : String(options.message);
        const hasMessage = messageText.trim().length > 0;
        messageEl.textContent = messageText;
        messageEl.classList.toggle('hidden', !hasMessage);

        passwordInput.value = '';
        passwordInput.setAttribute('autocomplete', autocompleteValue);
        confirmInput.value = '';
        confirmInput.setAttribute('autocomplete', requireConfirmation ? 'new-password' : 'off');
        confirmGroup.classList.toggle('hidden', !requireConfirmation);
        errorEl.textContent = '';
        errorEl.classList.add('hidden');
        submitBtn.textContent = submitLabel;

        modal.classList.add('active');

        const cleanup = (result) => {
            if (resolved) return;
            resolved = true;
            modal.classList.remove('active');
            passwordInput.value = '';
            confirmInput.value = '';
            form.removeEventListener('submit', onSubmit);
            cancelBtn.removeEventListener('click', onCancel);
            closeBtn.removeEventListener('click', onCancel);
            closeBtn.removeEventListener('keydown', onCloseKeydown);
            modal.removeEventListener('click', onBackdropClick);
            document.removeEventListener('keydown', onKeyDown);
            if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
                previouslyFocused.focus();
            }
            resolve(result);
        };

        const showError = (message) => {
            errorEl.textContent = message;
            errorEl.classList.remove('hidden');
        };

        const onSubmit = async (event) => {
            event.preventDefault();
            errorEl.classList.add('hidden');
            const password = passwordInput.value;
            if (!password.length) {
                showError('Password is required.');
                passwordInput.focus();
                return;
            }
            if (minLength && password.length < minLength) {
                showError(minLengthMessage);
                passwordInput.focus();
                passwordInput.select();
                return;
            }
            if (requireConfirmation) {
                const confirmation = confirmInput.value;
                if (!confirmation.length) {
                    showError('Please confirm the password.');
                    confirmInput.focus();
                    return;
                }
                if (password !== confirmation) {
                    showError('Passwords do not match.');
                    confirmInput.focus();
                    confirmInput.select();
                    return;
                }
            }
            if (validate) {
                submitBtn.disabled = true;
                let validationResult = null;
                try {
                    validationResult = await validate(password);
                } catch (error) {
                    validationResult = null;
                }
                submitBtn.disabled = false;
                if (!validationResult || !validationResult.ok) {
                    showError(validationResult && validationResult.message ? validationResult.message : 'Wrong password');
                    passwordInput.focus();
                    passwordInput.select();
                    return;
                }
            }
            cleanup(password);
        };

        const onCancel = () => cleanup(null);

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

        form.addEventListener('submit', onSubmit);
        cancelBtn.addEventListener('click', onCancel);
        closeBtn.addEventListener('click', onCancel);
        closeBtn.addEventListener('keydown', onCloseKeydown);
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onKeyDown);

        requestAnimationFrame(() => passwordInput.focus());
    });
}

function promptImportBackupModal() {
    return new Promise(resolve => {
        const modal = $('import-backup-modal');
        const titleEl = $('import-backup-title');
        const messageEl = $('import-backup-message');
        const form = $('import-backup-form');
        const nameInput = $('import-backup-name');
        const errorEl = $('import-backup-error');
        const cancelBtn = $('import-backup-cancel-btn');
        const submitBtn = $('import-backup-submit-btn');
        const closeBtn = $('import-backup-close');
        if (!modal || !titleEl || !messageEl || !form || !nameInput || !errorEl || !cancelBtn || !submitBtn || !closeBtn) {
            const fallback = window.prompt('Before importing, enter a backup file name. A timestamp will be added automatically.');
            resolve(fallback ? sanitizeBackupLabel(fallback) : null);
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
                previouslyFocused.focus();
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
            const rawName = nameInput.value;
            const sanitized = sanitizeBackupLabel(rawName);
            if (!sanitized) {
                showError('Enter a backup name using letters, numbers, spaces, dashes, or underscores.');
                nameInput.focus();
                return;
            }
            cleanup(sanitized);
        };

        const onCancel = () => cleanup(null);

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

        titleEl.textContent = 'Create import backup';
        messageEl.textContent = 'Before importing, a backup is required. Enter a short file name. We will save dialex-backup-<name>-YYYY-MM-DD-HH-MM-SS.enc in the save folder so you can restore if the import is wrong.';
        nameInput.value = '';
        errorEl.textContent = '';
        errorEl.classList.add('hidden');
        submitBtn.textContent = 'Create backup';

        modal.classList.add('active');
        form.addEventListener('submit', onSubmit);
        cancelBtn.addEventListener('click', onCancel);
        closeBtn.addEventListener('click', onCancel);
        closeBtn.addEventListener('keydown', onCloseKeydown);
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onKeyDown);

        requestAnimationFrame(() => nameInput.focus());
    });
}

function normalizeUsername(value) {
    return (value || '').toString().trim().toLowerCase();
}

function normalizeNamePart(value) {
    return (value || '').toString().trim().replace(/\s+/g, ' ');
}

function buildDisplayName(firstName, lastName) {
    const first = normalizeNamePart(firstName);
    const last = normalizeNamePart(lastName);
    return `${first} ${last}`.trim();
}

function hasRequiredNameParts(firstName, lastName) {
    return Boolean(normalizeNamePart(firstName) && normalizeNamePart(lastName));
}

function getCurrentUsername() {
    return currentUser && currentUser.username ? currentUser.username : '';
}

function isAdminUser() {
    return currentUser && currentUser.role === 'admin';
}

function updateAppAccessState() {
    const hasDb = Boolean(db);
    const hasUser = Boolean(currentUser);
    const hasSaveFolder = Boolean(saveDirectoryHandle && saveDirectoryReady);
    const unlocked = hasDb && hasUser;
    const canEdit = Boolean(unlocked && saveDirectoryReady && isAutosaveEncryptionReady());
    const assessmentControls = $('assessment-controls');
    const tableContainer = $('table-container');
    if (assessmentControls) assessmentControls.classList.toggle('hidden', !canEdit);
    if (tableContainer) tableContainer.classList.toggle('hidden', !canEdit);

    const loadDbRow = $('workflow-load-db-row');
    if (loadDbRow) loadDbRow.classList.toggle('hidden', !hasSaveFolder);
    const patientDataCard = $('patient-data-card');
    if (patientDataCard) patientDataCard.classList.toggle('hidden', !hasSaveFolder || !hasDb);

    const saveDbBtn = $('save-db-btn');
    if (saveDbBtn) saveDbBtn.disabled = !unlocked;
    const saveAllBtn = $('save-all-btn');
    if (saveAllBtn) saveAllBtn.disabled = !unlocked;
    const addPatientBtn = $('add-patient-btn');
    if (addPatientBtn) addPatientBtn.disabled = !canEdit;
    const registrationFile = $('registration-file');
    if (registrationFile) registrationFile.disabled = !canEdit;
    const registrationFileBtn = $('registration-file-btn');
    if (registrationFileBtn) registrationFileBtn.disabled = !canEdit;
    const registrationFileName = $('registration-file-name');
    if (registrationFileName) registrationFileName.classList.toggle('disabled', !canEdit);
    const unitFilterBtn = $('unit-filter-btn');
    if (unitFilterBtn) unitFilterBtn.disabled = !canEdit;

    const manageUsersBtn = $('manage-users-btn');
    if (manageUsersBtn) {
        const showManage = canEdit && isAdminUser();
        manageUsersBtn.classList.toggle('hidden', !showManage);
        manageUsersBtn.disabled = !showManage;
    }

    const signOutBtn = $('sign-out-btn');
    if (signOutBtn) {
        signOutBtn.classList.toggle('hidden', !unlocked);
        signOutBtn.disabled = !unlocked;
    }

    const rotateCentralBtn = $('rotate-central-btn');
    if (rotateCentralBtn) {
        const showCentral = canEdit && isAdminUser()
            && encryptionState
            && encryptionState.mode === 'multi'
            && encryptionState.unlockId === 'central';
        rotateCentralBtn.classList.toggle('hidden', !showCentral);
        rotateCentralBtn.disabled = !showCentral;
    }

    const adminGroup = $('admin-actions');
    if (adminGroup) {
        const showAdmin = [manageUsersBtn, signOutBtn, rotateCentralBtn]
            .some((btn) => btn && !btn.classList.contains('hidden'));
        adminGroup.classList.toggle('hidden', !showAdmin);
    }

    const userStatus = $('user-status');
    if (userStatus) {
        if (hasUser) {
            const label = currentUser.display_name
                ? `${currentUser.display_name} (${currentUser.username})`
                : currentUser.username;
            userStatus.textContent = label;
        } else {
            userStatus.textContent = 'Not signed in';
        }
    }
    updateAutosaveGate();
}

function setCurrentUser(user) {
    currentUser = user;
    updateAppAccessState();
    if (dbChanged) {
        queueAutosave();
    }
}

async function handleSignOut() {
    if (!db) return;
    const previousUser = currentUser ? { ...currentUser } : null;
    const result = await promptLoginModal({
        allowCancel: true,
        title: 'Switch user',
        message: 'Sign in as a different user, or cancel to stay signed in.'
    });
    if (!result) return;
    if (result.action === 'cancel') {
        showStatus('Switch user canceled.', 'status');
        return;
    }

    if (previousUser && previousUser.username) {
        logAuditEvent('user_signed_out', { username: previousUser.username }, {
            actorUsername: previousUser.username,
            actorRole: previousUser.role,
            targetType: 'user',
            targetId: previousUser.username
        });
    }

    if (result.action === 'unload') {
        unloadDatabase();
        return;
    }
    if (result.action === 'login' && result.user) {
        logAuditEvent('user_signed_in', { username: result.user.username }, {
            actorUsername: result.user.username,
            actorRole: result.user.role,
            targetType: 'user',
            targetId: result.user.username
        });
        setCurrentUser(result.user);
        showStatus('User switched.', 'success');
    }
}

function unloadDatabase() {
    db = null;
    patientsData = [];
    resetAutosaveTracking();
    encryptionState = null;
    currentUser = null;
    resetRecruitingUnitState();
    updateAppAccessState();
    renderPatientTable();
    updateFilterCounts();
    showStatus('No database loaded.', 'status');
}

const MAX_LOGIN_ATTEMPTS = 3;
const LOCKOUT_DURATION_MS = 5 * 60 * 1000;

function getUserCount() {
    if (!db) return 0;
    const stmt = db.prepare('SELECT COUNT(*) AS count FROM users');
    let count = 0;
    if (stmt.step()) {
        const row = stmt.getAsObject();
        count = Number(row.count) || 0;
    }
    stmt.free();
    return count;
}

function fetchUserByUsername(username) {
    if (!db) return null;
    const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    stmt.bind([username]);
    let user = null;
    if (stmt.step()) {
        user = stmt.getAsObject();
    }
    stmt.free();
    return user;
}

function getFailedAttemptsValue(value) {
    const attempts = Number(value);
    return Number.isFinite(attempts) && attempts > 0 ? attempts : 0;
}

function parseLockoutUntil(value) {
    if (value === null || value === undefined || value === '') return 0;
    const asNumber = Number(value);
    if (Number.isFinite(asNumber)) return asNumber;
    const parsed = new Date(value);
    const time = parsed.getTime();
    return Number.isNaN(time) ? 0 : time;
}

function formatLockoutRemaining(ms) {
    const totalSeconds = Math.max(1, Math.ceil(ms / 1000));
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    if (minutes <= 0) {
        return `${seconds}s`;
    }
    return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
}

function clearUserLock(username) {
    if (!db) return;
    const normalized = normalizeUsername(username);
    if (!normalized) return;
    const stmt = db.prepare(`
        UPDATE users
        SET failed_attempts = 0, locked = 0, locked_until = NULL, updated_at = ?
        WHERE username = ?
    `);
    stmt.run([getSqlTimestamp(), normalized]);
    stmt.free();
    markDatabaseChanged();
}

function recordFailedLoginAttempt(user) {
    if (!db || !user) return { attempts: 0, locked: false };
    const normalized = normalizeUsername(user.username || '');
    if (!normalized) return { attempts: 0, locked: false };
    const attempts = getFailedAttemptsValue(user.failed_attempts) + 1;
    const locked = attempts >= MAX_LOGIN_ATTEMPTS;
    const lockedUntil = locked ? Date.now() + LOCKOUT_DURATION_MS : null;
    const stmt = db.prepare(`
        UPDATE users
        SET failed_attempts = ?, locked = ?, locked_until = ?, updated_at = ?
        WHERE username = ?
    `);
    stmt.run([attempts, locked ? 1 : 0, lockedUntil, getSqlTimestamp(), normalized]);
    stmt.free();
    markDatabaseChanged();
    if (locked) {
        logAuditEvent('user_locked_out', { username: normalized, attempts }, {
            targetType: 'user',
            targetId: normalized
        });
    }
    return { attempts, locked: Boolean(locked), lockedUntil };
}

function getLockoutState(user, options = {}) {
    if (!user) return { locked: false, remainingMs: 0 };
    const now = Date.now();
    let lockedUntil = parseLockoutUntil(user.locked_until);
    if (!lockedUntil && Number(user.locked)) {
        lockedUntil = now + LOCKOUT_DURATION_MS;
        if (options.refreshDb) {
            const stmt = db.prepare(`
                UPDATE users
                SET locked = 1, locked_until = ?, updated_at = ?
                WHERE username = ?
            `);
            stmt.run([lockedUntil, getSqlTimestamp(), normalizeUsername(user.username || '')]);
            stmt.free();
            markDatabaseChanged();
        }
    }
    if (lockedUntil && lockedUntil > now) {
        return { locked: true, remainingMs: lockedUntil - now };
    }
    if (lockedUntil && lockedUntil <= now && options.refreshDb) {
        clearUserLock(user.username);
    }
    return { locked: false, remainingMs: 0 };
}

async function verifyCentralRecoveryPassword(password) {
    if (!password) {
        return { ok: false, message: 'Central recovery password is required.' };
    }
    if (!encryptionState || encryptionState.mode !== 'multi') {
        return { ok: false, message: 'Central recovery password is unavailable for this database.' };
    }
    const wraps = Array.isArray(encryptionState.wraps) ? encryptionState.wraps : [];
    const centralWrap = wraps.find(entry => entry && entry.id === 'central');
    if (!centralWrap) {
        return { ok: false, message: 'Central recovery password is unavailable for this database.' };
    }
    try {
        await unwrapDataKey(password, centralWrap);
        return { ok: true };
    } catch (error) {
        return { ok: false, message: 'Central recovery password is incorrect.' };
    }
}

function sanitizeUserRecord(user) {
    if (!user) return null;
    const sanitized = { ...user };
    delete sanitized.password_hash;
    delete sanitized.password_salt;
    return sanitized;
}

async function authenticateUser(username, password) {
    const normalized = normalizeUsername(username);
    if (!normalized) {
        return { ok: false, message: 'Username is required.' };
    }
    if (!password) {
        return { ok: false, message: 'Password is required.' };
    }
    const user = fetchUserByUsername(normalized);
    if (!user) {
        return { ok: false, message: 'Invalid username or password.' };
    }
    if (!Number(user.active)) {
        return { ok: false, message: 'This account is disabled.' };
    }
    const lockoutState = getLockoutState(user, { refreshDb: true });
    if (lockoutState.locked) {
        return {
            ok: false,
            message: `This account is locked. Try again in ${formatLockoutRemaining(lockoutState.remainingMs)} or sign in as a different user.`,
            locked: true,
            remainingMs: lockoutState.remainingMs
        };
    }
    const valid = await verifyPassword(password, user.password_salt, user.password_hash);
    if (!valid) {
        const attemptState = recordFailedLoginAttempt(user);
        if (attemptState.locked) {
            const remainingMs = attemptState.lockedUntil ? Math.max(attemptState.lockedUntil - Date.now(), 0) : LOCKOUT_DURATION_MS;
            return {
                ok: false,
                message: `Account locked. Try again in ${formatLockoutRemaining(remainingMs)} or sign in as a different user.`,
                locked: true,
                remainingMs
            };
        }
        const remaining = Math.max(MAX_LOGIN_ATTEMPTS - attemptState.attempts, 0);
        return {
            ok: false,
            message: `Invalid username or password. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
        };
    }
    clearUserLock(normalized);
    if (encryptionState && encryptionState.mode === 'multi') {
        const wrapId = getUserWrapId(normalized);
        const wraps = Array.isArray(encryptionState.wraps) ? encryptionState.wraps : [];
        const hasWrap = wrapId && wraps.some(entry => entry.id === wrapId);
        if (!hasWrap) {
            const updated = await upsertUserWrap(normalized, password);
            if (updated) {
                markDatabaseChanged();
                showStatus('Encryption access updated. Autosave will update the latest file.', 'status');
            }
        }
    }
    const resetRequired = Number(user.password_reset_required) ? true : false;
    const centralRecoveryAdmin = Boolean(
        encryptionState
        && encryptionState.mode === 'multi'
        && encryptionState.unlockId === 'central'
        && user.role === 'admin'
    );
    if (resetRequired || centralRecoveryAdmin) {
        const reason = centralRecoveryAdmin ? 'central_recovery' : 'admin_reset';
        return { ok: true, action: 'force_reset', reason, user: sanitizeUserRecord(user) };
    }
    return { ok: true, user: sanitizeUserRecord(user) };
}

async function createUserRecord({ username, firstName, lastName, password, role }) {
    const normalized = normalizeUsername(username);
    if (!normalized || !USERNAME_PATTERN.test(normalized)) {
        throw new Error('Usernames must be at least 3 characters and use letters, numbers, dots, underscores, or dashes.');
    }
    if (!hasRequiredNameParts(firstName, lastName)) {
        throw new Error('First name and last name are required.');
    }
    const displayName = buildDisplayName(firstName, lastName);
    if (!password || password.length < MIN_PASSWORD_LENGTH) {
        throw new Error(`Passwords must be at least ${MIN_PASSWORD_LENGTH} characters.`);
    }
    if (fetchUserByUsername(normalized)) {
        throw new Error('That username is already in use.');
    }
    const existingCount = getUserCount();
    const record = await createPasswordRecord(password);
    const stmt = db.prepare(`
        INSERT INTO users (username, display_name, password_salt, password_hash, role, active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    `);
    const timestamp = getSqlTimestamp();
    stmt.run([
        normalized,
        displayName,
        record.salt,
        record.hash,
        role || 'user',
        timestamp,
        timestamp
    ]);
    stmt.free();
    await upsertUserWrap(normalized, password);
    const createdUser = sanitizeUserRecord(fetchUserByUsername(normalized));
    const isBootstrap = existingCount === 0;
    logAuditEvent('user_created', {
        username: normalized,
        display_name: displayName,
        role: role || 'user',
        bootstrap: isBootstrap
    }, {
        actorUsername: getCurrentUsername() || (isBootstrap ? normalized : 'system'),
        actorRole: currentUser ? currentUser.role : (isBootstrap ? (role || 'user') : ''),
        targetType: 'user',
        targetId: normalized
    });
    return createdUser;
}

async function updateUserPassword(username, newPassword, options = {}) {
    const normalized = normalizeUsername(username);
    const record = await createPasswordRecord(newPassword);
    const resetRequired = options.resetRequired ? 1 : 0;
    const stmt = db.prepare(`
        UPDATE users
        SET password_salt = ?, password_hash = ?, failed_attempts = 0, locked = 0, locked_until = NULL,
            password_reset_required = ?, updated_at = ?
        WHERE username = ?
    `);
    stmt.run([record.salt, record.hash, resetRequired, getSqlTimestamp(), normalized]);
    stmt.free();
    await upsertUserWrap(normalized, newPassword);
    const action = options.action || (resetRequired ? 'user_password_reset' : 'user_password_changed');
    const details = options.details || { username: normalized };
    logAuditEvent(action, details, {
        targetType: 'user',
        targetId: normalized,
        actorUsername: options.actorUsername,
        actorRole: options.actorRole
    });
}

function loadUsers() {
    if (!db) return [];
    const stmt = db.prepare('SELECT username, display_name, role, active, locked, locked_until FROM users ORDER BY username');
    const users = [];
    while (stmt.step()) {
        users.push(stmt.getAsObject());
    }
    stmt.free();
    return users;
}

function countActiveAdmins(users) {
    return users.filter(user => user.role === 'admin' && Number(user.active)).length;
}

function renderUserManagementList() {
    const tbody = $('user-management-body');
    if (!tbody) return;
    const users = loadUsers();
    tbody.innerHTML = '';
    users.forEach(user => {
        const row = document.createElement('tr');
        const roleLabel = user.role === 'admin' ? 'Admin' : 'User';
        const lockoutState = getLockoutState(user, { refreshDb: true });
        const statusLabel = Number(user.active)
            ? (lockoutState.locked ? 'Locked' : 'Active')
            : 'Disabled';
        row.innerHTML = `
            <td>${escapeHtml(user.username || '')}</td>
            <td>${escapeHtml(user.display_name || '')}</td>
            <td>${roleLabel}</td>
            <td>${statusLabel}</td>
            <td>
                <button type="button" class="secondary" data-action="reset" data-username="${escapeHtml(user.username || '')}">Reset password</button>
                <button type="button" class="secondary" data-action="toggle" data-username="${escapeHtml(user.username || '')}">
                    ${Number(user.active) ? 'Disable' : 'Enable'}
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function openUserManagementModal() {
    if (!isAdminUser()) return;
    const modal = $('user-management-modal');
    if (!modal) return;
    renderUserManagementList();
    const errorEl = $('user-management-error');
    if (errorEl) {
        errorEl.textContent = '';
        errorEl.classList.add('hidden');
    }
    modal.classList.add('active');
}

function closeUserManagementModal() {
    const modal = $('user-management-modal');
    if (!modal) return;
    modal.classList.remove('active');
}

async function handleUserManagementAction(action, username) {
    const users = loadUsers();
    const target = users.find(user => user.username === username);
    if (!target) return;
    const activeAdmins = countActiveAdmins(users);
    if (action === 'toggle') {
        if (target.username === getCurrentUsername()) {
            showStatus('You cannot disable the account you are signed in with.', 'error');
            return;
        }
        if (target.role === 'admin' && Number(target.active) && activeAdmins <= 1) {
            showStatus('At least one active admin is required.', 'error');
            return;
        }
        const nextActive = Number(target.active) ? 0 : 1;
        const stmt = db.prepare(`
        UPDATE users
        SET active = ?, updated_at = ?
        WHERE username = ?
        `);
        stmt.run([nextActive, getSqlTimestamp(), target.username]);
        stmt.free();
        if (!nextActive) {
            removeUserWrap(target.username);
        }
        markDatabaseChanged();
        logAuditEvent(nextActive ? 'user_enabled' : 'user_disabled', {
            username: target.username,
            active: nextActive
        }, {
            targetType: 'user',
            targetId: target.username
        });
        renderUserManagementList();
        if (nextActive && encryptionState && encryptionState.mode === 'multi') {
            const wrapId = getUserWrapId(target.username);
            const wraps = Array.isArray(encryptionState.wraps) ? encryptionState.wraps : [];
            if (wrapId && !wraps.some(entry => entry.id === wrapId)) {
                showStatus('User enabled. Reset their password to restore decryption access.', 'status');
            }
        }
        return;
    }
    if (action === 'reset') {
        const newPassword = await promptPasswordModal({
            title: `Reset password for ${target.username}`,
            message: `Create a new password for ${target.username}.`,
            requireConfirmation: true,
            submitLabel: 'Reset password',
            autocomplete: 'new-password',
            minLength: MIN_PASSWORD_LENGTH
        });
        if (!newPassword) return;
        await updateUserPassword(target.username, newPassword, {
            resetRequired: true,
            action: 'user_password_reset',
            details: { username: target.username, reset_required: true }
        });
        markDatabaseChanged();
        showStatus('Temporary password set. The user will be prompted to set a new password at sign-in.', 'success');
        return;
    }
}

async function promptLoginModal(options = {}) {
    return new Promise(resolve => {
        const modal = $('login-modal');
        const titleEl = $('login-modal-title');
        const messageEl = $('login-modal-message');
        const form = $('login-form');
        const usernameInput = $('login-username');
        const passwordGroup = $('login-password-group');
        const passwordInput = $('login-password');
        const errorEl = $('login-error');
        const recoveryBanner = $('login-recovery-banner');
        const cancelBtn = $('login-cancel-btn');
        const unloadBtn = $('login-unload-btn');
        const resetBtn = $('login-reset-btn');
        const submitBtn = $('login-submit-btn');
        const closeBtn = $('login-modal-close');
        const previouslyFocused = document.activeElement;
        const allowCancel = Boolean(options.allowCancel);
        const authenticate = typeof options.authenticate === 'function' ? options.authenticate : authenticateUser;
        const recover = typeof options.recover === 'function' ? options.recover : null;
        const submitLabel = options.submitLabel || 'Sign in';
        const recoveryLabel = options.recoveryLabel || (recover ? 'Use central recovery password' : 'Reset password');
        const showReset = options.showReset !== false;
        const unloadLabel = options.unloadLabel || 'Unload database';
        const passwordAutocomplete = options.passwordAutocomplete || 'current-password';
        const recoveryMode = Boolean(options.recoveryMode);
        const recoveryMessage = options.recoveryMessage || 'Recovery mode: reset your password to continue.';
        const showPassword = options.showPassword !== false;
        let resolved = false;
        let lockoutTimer = null;
        let lockoutExpiresAt = 0;

        const clearLockoutTimer = () => {
            if (lockoutTimer) {
                clearInterval(lockoutTimer);
                lockoutTimer = null;
            }
            lockoutExpiresAt = 0;
            if (passwordInput && showPassword) {
                passwordInput.disabled = false;
            }
            if (submitBtn) {
                submitBtn.disabled = false;
            }
        };

        const cleanup = (result) => {
            if (resolved) return;
            resolved = true;
            modal.classList.remove('active');
            clearLockoutTimer();
            form.removeEventListener('submit', onSubmit);
            if (cancelBtn) cancelBtn.removeEventListener('click', onCancel);
            if (unloadBtn) unloadBtn.removeEventListener('click', onUnload);
            if (resetBtn) resetBtn.removeEventListener('click', onReset);
            if (closeBtn) {
                closeBtn.removeEventListener('click', onCancel);
                closeBtn.removeEventListener('keydown', onCloseKeydown);
            }
            modal.removeEventListener('click', onBackdropClick);
            document.removeEventListener('keydown', onKeyDown);
            if (usernameInput) {
                usernameInput.removeEventListener('input', onUsernameInput);
            }
            if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
                previouslyFocused.focus();
            }
            resolve(result);
        };

        const showError = (message) => {
            errorEl.textContent = message;
            errorEl.classList.remove('hidden');
        };

        const updateLockoutMessage = () => {
            if (!lockoutExpiresAt) return;
            const remainingMs = lockoutExpiresAt - Date.now();
            if (remainingMs <= 0) {
                clearLockoutTimer();
                errorEl.textContent = '';
                errorEl.classList.add('hidden');
                return;
            }
            showError(`This account is locked. Try again in ${formatLockoutRemaining(remainingMs)} or sign in as a different user.`);
        };

        const runForcedPasswordReset = async (user, reason) => {
            if (!user || !user.username) {
                showError('Unable to update the password.');
                return null;
            }
            const normalized = normalizeUsername(user.username);
            const displayName = user.display_name ? `${user.display_name} (${normalized})` : normalized;
            const isCentralRecovery = reason === 'central_recovery';
            const message = isCentralRecovery
                ? 'Central recovery was used to unlock this database. Set a new admin password now.'
                : `Your password was reset by an admin. Create a new password for ${displayName}.`;
            while (true) {
                let newPassword = await promptPasswordModal({
                    title: 'Set new password',
                    message,
                    requireConfirmation: true,
                    submitLabel: 'Update password',
                    autocomplete: 'new-password',
                    minLength: MIN_PASSWORD_LENGTH
                });
                if (!newPassword) {
                    showError('Password reset is required to continue.');
                    return null;
                }
                await updateUserPassword(normalized, newPassword, {
                    action: 'user_password_changed',
                    details: { username: normalized, reason: isCentralRecovery ? 'central_recovery' : 'admin_reset' },
                    actorUsername: normalized,
                    actorRole: user.role
                });
                markDatabaseChanged();
                clearLockoutTimer();
                newPassword = null;
                const refreshed = sanitizeUserRecord(fetchUserByUsername(normalized));
                if (!refreshed) {
                    showError('Password updated, but the account could not be loaded.');
                    return null;
                }
                return refreshed;
            }
        };

        const startLockoutTimer = (remainingMs) => {
            if (!remainingMs || remainingMs <= 0) return;
            clearLockoutTimer();
            lockoutExpiresAt = Date.now() + remainingMs;
            if (passwordInput && showPassword) {
                passwordInput.disabled = true;
            }
            if (submitBtn) {
                submitBtn.disabled = true;
            }
            updateLockoutMessage();
            lockoutTimer = setInterval(updateLockoutMessage, 1000);
        };

        const onSubmit = async (event) => {
            event.preventDefault();
            errorEl.textContent = '';
            errorEl.classList.add('hidden');
            const username = usernameInput.value;
            const password = passwordInput.value;
            clearLockoutTimer();
            submitBtn.disabled = true;
            const result = await authenticate(username, password);
            submitBtn.disabled = false;
            if (!result.ok) {
                showError(result.message || 'Unable to sign in.');
                if (result.locked && result.remainingMs) {
                    startLockoutTimer(result.remainingMs);
                }
                if (showPassword) {
                    passwordInput.focus();
                    passwordInput.select();
                } else if (usernameInput) {
                    usernameInput.focus();
                    usernameInput.select();
                }
                return;
            }
            if (result.action === 'force_reset') {
                const updatedUser = await runForcedPasswordReset(result.user, result.reason);
                if (!updatedUser) {
                    return;
                }
                cleanup({ action: 'login', user: updatedUser });
                return;
            }
            cleanup({ action: result.action || 'login', user: result.user });
        };

        const onReset = async () => {
            errorEl.textContent = '';
            errorEl.classList.add('hidden');
            if (recover) {
                resetBtn.disabled = true;
                const recoveryResult = await recover({
                    username: usernameInput ? usernameInput.value : ''
                });
                resetBtn.disabled = false;
                if (recoveryResult && recoveryResult.canceled) {
                    return;
                }
                if (!recoveryResult || !recoveryResult.ok) {
                    if (recoveryResult && recoveryResult.message) {
                        showError(recoveryResult.message);
                    } else {
                        showError('Unable to verify recovery password.');
                    }
                    return;
                }
                cleanup({ action: recoveryResult.action || 'recovery', user: recoveryResult.user });
                return;
            }
            const username = usernameInput ? usernameInput.value : '';
            const normalized = normalizeUsername(username);
            if (!normalized) {
                showError('Enter a username to reset.');
                if (usernameInput) {
                    usernameInput.focus();
                }
                return;
            }
            const target = fetchUserByUsername(normalized);
            if (!target) {
                showError('That username was not found.');
                if (usernameInput) {
                    usernameInput.focus();
                }
                return;
            }
            let centralPassword = await promptPasswordModal({
                title: 'Central recovery password',
                message: `Ask your local administrator (usually the site PI) to reset your password first. If the admin has lost their password, the admin should contact the project office at fixdialysis@lhsc.on.ca to obtain a recovery password. Enter the central recovery password to reset ${normalized}.`,
                requireConfirmation: false,
                submitLabel: 'Verify',
                autocomplete: 'current-password',
                validate: async (password) => {
                    const check = await verifyCentralRecoveryPassword(password);
                    if (!check.ok) {
                        return { ok: false, message: 'Wrong password' };
                    }
                    return { ok: true };
                }
            });
            if (!centralPassword) return;
            centralPassword = null;
            let newPassword = await promptPasswordModal({
                title: `Reset password for ${normalized}`,
                message: `Create and confirm a new password for ${normalized}.`,
                requireConfirmation: true,
                submitLabel: 'Reset password',
                autocomplete: 'new-password',
                minLength: MIN_PASSWORD_LENGTH
            });
            if (!newPassword) return;
            await updateUserPassword(normalized, newPassword, {
                action: 'user_password_changed',
                details: { username: normalized, reason: 'central_recovery' },
                actorUsername: normalized,
                actorRole: target.role
            });
            markDatabaseChanged();
            newPassword = null;
            clearLockoutTimer();
            if (passwordInput) {
                passwordInput.value = '';
                passwordInput.focus();
            }
            showStatus('Password updated. Sign in with the new password.', 'success');
        };

        const onUsernameInput = () => {
            clearLockoutTimer();
            errorEl.textContent = '';
            errorEl.classList.add('hidden');
            if (passwordInput) {
                passwordInput.value = '';
            }
        };

        const onCancel = () => cleanup({ action: 'cancel' });
        const onUnload = () => cleanup({ action: 'unload' });

        const onBackdropClick = (event) => {
            if (!allowCancel) return;
            if (event.target === modal) {
                onCancel();
            }
        };

        const onKeyDown = (event) => {
            if (!allowCancel) return;
            if (event.key === 'Escape') {
                event.preventDefault();
                onCancel();
            }
        };

        const onCloseKeydown = (event) => {
            if (!allowCancel) return;
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                onCancel();
            }
        };

        if (titleEl) titleEl.textContent = options.title || 'Sign in';
        if (messageEl) messageEl.textContent = options.message || 'Database loaded. Sign in to continue.';
        if (recoveryBanner) {
            recoveryBanner.textContent = recoveryMessage;
            recoveryBanner.classList.toggle('hidden', !recoveryMode);
        }
        if (passwordGroup) {
            passwordGroup.classList.toggle('hidden', !showPassword);
        }
        usernameInput.value = '';
        passwordInput.value = '';
        passwordInput.setAttribute('autocomplete', passwordAutocomplete);
        passwordInput.required = showPassword;
        passwordInput.disabled = !showPassword;
        errorEl.textContent = '';
        errorEl.classList.add('hidden');

        if (cancelBtn) cancelBtn.classList.toggle('hidden', !allowCancel);
        if (closeBtn) closeBtn.classList.toggle('hidden', !allowCancel);
        if (resetBtn) {
            resetBtn.classList.toggle('hidden', !showReset);
            resetBtn.textContent = recoveryLabel;
        }
        if (submitBtn) submitBtn.textContent = submitLabel;
        if (unloadBtn) unloadBtn.textContent = unloadLabel;
        modal.classList.add('active');

        form.addEventListener('submit', onSubmit);
        if (cancelBtn) cancelBtn.addEventListener('click', onCancel);
        if (unloadBtn) unloadBtn.addEventListener('click', onUnload);
        if (resetBtn) resetBtn.addEventListener('click', onReset);
        if (closeBtn) {
            closeBtn.addEventListener('click', onCancel);
            closeBtn.addEventListener('keydown', onCloseKeydown);
        }
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onKeyDown);
        if (usernameInput) {
            usernameInput.addEventListener('input', onUsernameInput);
        }
        requestAnimationFrame(() => usernameInput.focus());
    });
}
