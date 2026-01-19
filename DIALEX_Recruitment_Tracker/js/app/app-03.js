
async function promptInitialAdminSetup() {
    return new Promise(resolve => {
        const modal = $('admin-setup-modal');
        const form = $('admin-setup-form');
        const usernameInput = $('admin-username');
        const firstNameInput = $('admin-first-name');
        const lastNameInput = $('admin-last-name');
        const passwordInput = $('admin-password');
        const confirmInput = $('admin-password-confirm');
        const errorEl = $('admin-setup-error');
        const unloadBtn = $('admin-setup-unload-btn');
        const submitBtn = $('admin-setup-submit-btn');
        const previouslyFocused = document.activeElement;
        let resolved = false;

        const cleanup = (result) => {
            if (resolved) return;
            resolved = true;
            modal.classList.remove('active');
            form.removeEventListener('submit', onSubmit);
            if (unloadBtn) unloadBtn.removeEventListener('click', onUnload);
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
            errorEl.textContent = '';
            errorEl.classList.add('hidden');
            const username = usernameInput.value;
            const firstName = normalizeNamePart(firstNameInput.value);
            const lastName = normalizeNamePart(lastNameInput.value);
            const password = passwordInput.value;
            const confirm = confirmInput.value;
            if (!username || !USERNAME_PATTERN.test(normalizeUsername(username))) {
                showError('Enter a valid username (letters, numbers, dot, underscore, dash).');
                usernameInput.focus();
                return;
            }
            if (!hasRequiredNameParts(firstName, lastName)) {
                showError('Enter both first name and last name.');
                if (!firstName) {
                    firstNameInput.focus();
                } else {
                    lastNameInput.focus();
                }
                return;
            }
            if (!password || password.length < MIN_PASSWORD_LENGTH) {
                showError(`Passwords must be at least ${MIN_PASSWORD_LENGTH} characters.`);
                passwordInput.focus();
                return;
            }
            if (password !== confirm) {
                showError('Passwords do not match.');
                confirmInput.focus();
                confirmInput.select();
                return;
            }
            submitBtn.disabled = true;
            try {
                const user = await createUserRecord({
                    username,
                    firstName,
                    lastName,
                    password,
                    role: 'admin'
                });
                markDatabaseChanged();
                cleanup(user);
            } catch (error) {
                console.error(error);
                showError(error.message || 'Unable to create admin user.');
            } finally {
                submitBtn.disabled = false;
            }
        };

        const onUnload = () => {
            cleanup(null);
            unloadDatabase();
        };

        usernameInput.value = '';
        firstNameInput.value = '';
        lastNameInput.value = '';
        passwordInput.value = '';
        confirmInput.value = '';
        errorEl.textContent = '';
        errorEl.classList.add('hidden');
        modal.classList.add('active');

        form.addEventListener('submit', onSubmit);
        if (unloadBtn) unloadBtn.addEventListener('click', onUnload);
        requestAnimationFrame(() => usernameInput.focus());
    });
}

async function handlePostLoadLogin() {
    if (!db) return;
    currentUser = null;
    updateAppAccessState();
    const userCount = getUserCount();
    if (userCount === 0) {
        const adminUser = await promptInitialAdminSetup();
        if (adminUser) {
            setCurrentUser(adminUser);
            logAuditEvent('user_signed_in', { username: adminUser.username }, {
                actorUsername: adminUser.username,
                actorRole: adminUser.role,
                targetType: 'user',
                targetId: adminUser.username
            });
            showStatus('Admin account created. Autosave will update the latest file.', 'success');
        }
        return;
    }
    const result = await promptLoginModal({ allowCancel: false });
    if (result && result.action === 'unload') {
        unloadDatabase();
        return;
    }
    if (result && result.action === 'login' && result.user) {
        logAuditEvent('user_signed_in', { username: result.user.username }, {
            actorUsername: result.user.username,
            actorRole: result.user.role,
            targetType: 'user',
            targetId: result.user.username
        });
        setCurrentUser(result.user);
    }
}

async function handleRotateCentralPassword() {
    if (!encryptionState || encryptionState.mode !== 'multi') {
        showStatus('Central password rotation is unavailable.', 'error');
        return;
    }
    if (encryptionState.unlockId !== 'central') {
        showStatus('Open the database with the central password to rotate it.', 'error');
        return;
    }
    const newPassword = await promptPasswordModal({
        title: 'Rotate central password',
        message: 'Create and confirm a new central recovery password.',
        requireConfirmation: true,
        submitLabel: 'Update password',
        autocomplete: 'new-password'
    });
    if (!newPassword) return;
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
        showStatus(`Passwords must be at least ${MIN_PASSWORD_LENGTH} characters.`, 'error');
        return;
    }
    const newWrap = await wrapDataKey(encryptionState.dataKey, newPassword);
    const wraps = Array.isArray(encryptionState.wraps) ? encryptionState.wraps : [];
    const index = wraps.findIndex(entry => entry.id === 'central');
    const updated = { id: 'central', ...newWrap };
    if (index >= 0) {
        wraps[index] = updated;
    } else {
        wraps.push(updated);
    }
    encryptionState.wraps = wraps;
    markDatabaseChanged();
    logAuditEvent('central_password_rotated', null, {
        targetType: 'encryption',
        targetId: 'central'
    });
    showStatus('Central password updated. Autosave will update the latest file.', 'success');
}

function setupUserManagementControls() {
    const modal = $('user-management-modal');
    if (!modal) return;
    const closeBtn = $('user-management-close');
    const doneBtn = $('user-management-done-btn');
    const form = $('user-create-form');
    const errorEl = $('user-management-error');
    const tbody = $('user-management-body');

    const closeModal = () => {
        modal.classList.remove('active');
    };

    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (doneBtn) doneBtn.addEventListener('click', closeModal);
    modal.addEventListener('click', (event) => {
        if (event.target === modal) {
            closeModal();
        }
    });

    if (tbody) {
        tbody.addEventListener('click', async (event) => {
            const button = event.target.closest('button[data-action]');
            if (!button) return;
            const action = button.dataset.action;
            const username = button.dataset.username;
            await handleUserManagementAction(action, username);
        });
    }

    if (form) {
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            if (!db) return;
            if (errorEl) {
                errorEl.textContent = '';
                errorEl.classList.add('hidden');
            }
            const usernameInput = $('user-create-username');
            const firstNameInput = $('user-create-first-name');
            const lastNameInput = $('user-create-last-name');
            const roleInput = $('user-create-role');
            const passwordInput = $('user-create-password');
            const confirmInput = $('user-create-confirm');
            const username = usernameInput ? usernameInput.value : '';
            const firstName = normalizeNamePart(firstNameInput ? firstNameInput.value : '');
            const lastName = normalizeNamePart(lastNameInput ? lastNameInput.value : '');
            const role = roleInput ? roleInput.value : 'user';
            const password = passwordInput ? passwordInput.value : '';
            const confirmation = confirmInput ? confirmInput.value : '';
            if (!username || !USERNAME_PATTERN.test(normalizeUsername(username))) {
                if (errorEl) {
                    errorEl.textContent = 'Enter a valid username (letters, numbers, dot, underscore, dash).';
                    errorEl.classList.remove('hidden');
                }
                return;
            }
            if (!hasRequiredNameParts(firstName, lastName)) {
                if (errorEl) {
                    errorEl.textContent = 'Enter both first name and last name.';
                    errorEl.classList.remove('hidden');
                }
                return;
            }
            if (!password || password.length < MIN_PASSWORD_LENGTH) {
                if (errorEl) {
                    errorEl.textContent = `Passwords must be at least ${MIN_PASSWORD_LENGTH} characters.`;
                    errorEl.classList.remove('hidden');
                }
                return;
            }
            if (password !== confirmation) {
                if (errorEl) {
                    errorEl.textContent = 'Passwords do not match.';
                    errorEl.classList.remove('hidden');
                }
                return;
            }
            try {
                await createUserRecord({ username, firstName, lastName, password, role });
                markDatabaseChanged();
                if (usernameInput) usernameInput.value = '';
                if (firstNameInput) firstNameInput.value = '';
                if (lastNameInput) lastNameInput.value = '';
                if (roleInput) roleInput.value = 'user';
                if (passwordInput) passwordInput.value = '';
                if (confirmInput) confirmInput.value = '';
                renderUserManagementList();
                showStatus('User added.', 'success');
            } catch (error) {
                console.error(error);
                if (errorEl) {
                    errorEl.textContent = error.message || 'Unable to add user.';
                    errorEl.classList.remove('hidden');
                }
            }
        });
    }
}


function toggleCriteriaReference() {
    const content = $('criteria-content');
    const chevron = $('criteria-chevron');
    content.classList.toggle('open');
    chevron.style.transform = content.classList.contains('open') ? 'rotate(180deg)' : 'rotate(0deg)';
}

function toggleInstructions() {
    const content = $('instructions-content');
    const chevron = $('instructions-chevron');
    if (!content || !chevron) return;
    content.classList.toggle('open');
    chevron.style.transform = content.classList.contains('open') ? 'rotate(180deg)' : 'rotate(0deg)';
}

async function createNewDatabase() {
    if (!ALLOW_DATABASE_CREATION) {
        showStatus('Database creation is disabled in this build.', 'error');
        return;
    }
    if (db && dbChanged && !confirm('You have unsaved changes. Continue anyway?')) return;
    db = new SQL.Database();
    setupDatabase();
    loadRecruitingUnitState();
    resetAutosaveTracking();
    encryptionState = null;
    currentUser = null;
    patientsData = [];
    renderPatientTable();
    updateFilterCounts();
    updateAppAccessState();
    showStatus('New database created. Create an admin account to continue.', 'success');
    await handlePostLoadLogin();
}

function setupDatabase() {
    if (!db) return;
    db.run(`
        CREATE TABLE IF NOT EXISTS patient_assessments (
            mrn TEXT PRIMARY KEY,
            patient_name TEXT NOT NULL,
            age INTEGER,
            location TEXT,
            location_at_notification TEXT,
            location_at_randomization TEXT,
            health_card TEXT,
            health_card_province TEXT,
            birth_date TEXT,
            dialysis_start_date TEXT,
            notification_date TEXT,
            opt_out_status TEXT DEFAULT 'pending',
            opt_out_date TEXT,
            randomization_date TEXT,
            randomized INTEGER DEFAULT 0,
            allocation TEXT,
            notes TEXT,
            enrollment_status TEXT DEFAULT 'pending',
            therapy_prescribed INTEGER DEFAULT 0,
            did_not_opt_out INTEGER DEFAULT 0,
            dialysis_duration_confirmed INTEGER DEFAULT 0,
            study_id TEXT,
            locked_at TEXT,
            diabetes_known INTEGER DEFAULT 0,
            incl_age INTEGER DEFAULT 0,
            incl_dialysis_90d INTEGER DEFAULT 0,
            incl_incentre_hd INTEGER DEFAULT 0,
            incl_health_card INTEGER DEFAULT 0,
            excl_hd_less3 INTEGER DEFAULT 0,
            excl_intolerance INTEGER DEFAULT 0,
            excl_hdf_planned INTEGER DEFAULT 0,
            excl_nocturnal INTEGER DEFAULT 0,
            excl_discontinue INTEGER DEFAULT 0,
            excl_nonadherence INTEGER DEFAULT 0,
            excl_preference INTEGER DEFAULT 0,
            excl_other_medical INTEGER DEFAULT 0,
            excl_other_trial INTEGER DEFAULT 0,
            excl_previous INTEGER DEFAULT 0,
            excl_declined INTEGER DEFAULT 0,
            no_exclusions_confirmed INTEGER DEFAULT 0,
            entry_source TEXT,
            created_by TEXT,
            updated_by TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT DEFAULT CURRENT_TIMESTAMP,
            actor_username TEXT,
            actor_role TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            details TEXT
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS study_ids (
            study_id TEXT PRIMARY KEY,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS site_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN therapy_prescribed INTEGER DEFAULT 0`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add therapy_prescribed column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN location_at_notification TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add location_at_notification column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN location_at_randomization TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add location_at_randomization column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN did_not_opt_out INTEGER DEFAULT 0`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add did_not_opt_out column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN randomization_date TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add randomization_date column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN randomized INTEGER DEFAULT 0`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add randomized column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN birth_date TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add birth_date column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN dialysis_duration_confirmed INTEGER DEFAULT 0`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add dialysis_duration_confirmed column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN opt_out_status TEXT DEFAULT 'pending'`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add opt_out_status column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN opt_out_date TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add opt_out_date column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN allocation TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add allocation column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN study_id TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add study_id column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN locked_at TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add locked_at column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN diabetes_known INTEGER DEFAULT 0`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add diabetes_known column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN no_exclusions_confirmed INTEGER DEFAULT 0`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add no_exclusions_confirmed column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN entry_source TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add entry_source column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN created_by TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add created_by column', error);
        }
    }
    try {
        db.run(`ALTER TABLE patient_assessments ADD COLUMN updated_by TEXT`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add updated_by column', error);
        }
    }
    try {
        db.run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add role column', error);
        }
    }
    try {
        db.run(`ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1`);
    } catch (error) {
        if (!/duplicate column/i.test((error && error.message) || '')) {
            console.warn('Unable to add active column', error);
        }
    }
}

function enableAppControls() {
    updateAppAccessState();
}

async function loadDatabase(event) {
    const file = event.target.files[0];
    if (!file) return;
    event.target.value = '';
    const filename = file.name || '';
    const isBackupFile = isImportBackupFilename(filename);
    if (isBackupFile) {
        const proceed = window.confirm(
            'You selected a backup file. Backups can be outdated and should only be loaded to fix a clear problem (for example, a bad import). Continue?'
        );
        if (!proceed) {
            showStatus('Load canceled.', 'status');
            return;
        }
    }

    const readBytes = (inputFile) => new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(new Uint8Array(reader.result));
        reader.onerror = () => reject(new Error('Error reading file.'));
        reader.readAsArrayBuffer(inputFile);
    });

    let data;
    try {
        showStatus('Reading file...', 'status');
        data = await readBytes(file);
    } catch (error) {
        console.error(error);
        showStatus('Error reading file.', 'error');
        return;
    }

    const isV2 = isV2EncryptedPayload(data);
    let password = await promptPasswordModal({
        title: 'Decrypt database',
        message: isV2
            ? (file.name
                ? `Enter your account password (or the central recovery password) for "${file.name}".`
                : 'Enter your account password (or the central recovery password) to decrypt this database.')
            : (file.name
                ? `Enter the database encryption password for "${file.name}".`
                : 'Enter the database encryption password to decrypt this database.'),
        submitLabel: 'Decrypt',
        autocomplete: 'current-password'
    });
    if (!password) return;

    try {
        showStatus('Decrypting...', 'status');
        const decrypted = await decryptDatabasePayload(data, password);
        password = null;

        db = new SQL.Database(decrypted.dataBytes);
        encryptionState = decrypted.encryptionState;
        currentUser = null;
        setupDatabase();
        loadRecruitingUnitState();
        refreshPatientData();
        resetAutosaveTracking();
        saveDirectoryReady = false;
        await restoreSavedDirectoryHandle();
        await validateSaveDirectoryForAutosave({ showStatus: false, requestPermission: true });
        updateAppAccessState();
        const autosaveMessage = getAutosaveBlockingMessage();
        const backupWarning = isBackupFile
            ? 'Backup file loaded. Backups can be outdated; use them only to correct a known problem.'
            : '';
        if (autosaveMessage) {
            const combined = backupWarning ? `${autosaveMessage} ${backupWarning}` : autosaveMessage;
            showStatus(`Loaded secure database: ${file.name}. ${combined}`, 'error');
        } else if (backupWarning) {
            showStatus(`Loaded secure database: ${file.name}. ${backupWarning}`, 'status');
        } else {
            showStatus(`Loaded secure database: ${file.name}`, 'success');
        }
        await handlePostLoadLogin();
    } catch (error) {
        console.error(error);
        showStatus('Error: ' + error.message, 'error');
    } finally {
        password = null;
    }
}

async function saveDatabase() {
    if (!db) { showStatus('Create or load a database first.', 'error'); return; }
    if (!currentUser) { showStatus('Sign in to save the database.', 'error'); return; }

    if (autosaveInProgress) {
        showStatus('Autosave in progress. Please wait...', 'status');
        await waitForAutosaveToFinish();
    }

    manualSaveInProgress = true;
    const changeSnapshot = dbChangeCounter;
    try {
        if (!await ensureEncryptionStateForSave()) return;

        showStatus('Encrypting...', 'status');
        const sqlData = db.export();
        let encryptedData;
        if (encryptionState && encryptionState.mode === 'multi') {
            encryptedData = await encryptDatabaseV2(sqlData, encryptionState);
        } else {
            let password = await promptPasswordModal({
                title: 'Set encryption password',
                message: 'Create and confirm a password for this encrypted export. You will need it again to reopen the file.',
                requireConfirmation: true,
                submitLabel: 'Encrypt & Save',
                autocomplete: 'new-password'
            });
            if (!password) return;
            encryptedData = await encryptData(sqlData, password);
            password = null;
        }

        const blob = new Blob([encryptedData], { type: 'application/octet-stream' });
        const timestamp = formatTimestampForFilename();
        const filename = `dialex-secure-${timestamp}.enc`;

        const saveResult = await persistEncryptedDatabase(blob, filename);

        if (saveResult === 'cancelled') {
            showStatus('Save canceled.', 'status');
            return;
        }

        if (!saveResult) {
            triggerBrowserDownload(blob, filename);
        }

        if (dbChangeCounter === changeSnapshot) {
            setDatabaseClean();
        }

        showStatus('Database encrypted and saved.', 'success');
        updateAppAccessState();
    } catch (error) {
        console.error(error);
        showStatus('Error saving database: ' + error.message, 'error');
    } finally {
        manualSaveInProgress = false;
        if (dbChanged) {
            queueAutosave();
        }
    }
}

async function persistEncryptedDatabase(blob, filename) {
    if (saveDirectoryHandle) {
        const folderResult = await saveWithSelectedDirectory(blob, filename);
        if (folderResult === true || folderResult === 'cancelled') {
            return folderResult;
        }
    }
    if (supportsSaveFilePicker) {
        return await saveWithSavePicker(blob, filename);
    }
    return false;
}

async function saveWithSelectedDirectory(blob, filename) {
    try {
        const allowed = await ensureDirectoryPermission(saveDirectoryHandle);
        if (!allowed) {
            showStatus('Permission to write to the selected save folder was denied. Please choose another folder.', 'error');
            saveDirectoryHandle = null;
            saveDirectoryReady = false;
            await clearStoredSaveDirectoryHandle();
            updateSaveFolderStatus();
            updateAppAccessState();
            return false;
        }
        const fileHandle = await saveDirectoryHandle.getFileHandle(filename, { create: true });
        await writeBlobToHandle(fileHandle, blob);
        return true;
    } catch (error) {
        if (error && error.name === 'AbortError') {
            return 'cancelled';
        }
        console.error('Unable to save inside the selected folder', error);
        showStatus('Unable to save inside the selected folder: ' + (error && error.message ? error.message : error), 'error');
        saveDirectoryHandle = null;
        saveDirectoryReady = false;
        await clearStoredSaveDirectoryHandle();
        updateSaveFolderStatus();
        updateAppAccessState();
        return false;
    }
}

async function saveWithSavePicker(blob, filename) {
    try {
        const fileHandle = await window.showSaveFilePicker({
            suggestedName: filename,
            types: [{
                description: 'Encrypted DIALEX database',
                accept: { 'application/octet-stream': ['.enc'] }
            }]
        });
        const allowed = await ensureDirectoryPermission(fileHandle);
        if (!allowed) {
            showStatus('Permission to write the selected file was denied.', 'error');
            return false;
        }
        await writeBlobToHandle(fileHandle, blob);
        return true;
    } catch (error) {
        if (error && error.name === 'AbortError') {
            return 'cancelled';
        }
        console.error('Save picker error', error);
        showStatus('Unable to save database: ' + (error && error.message ? error.message : error), 'error');
        return false;
    }
}

async function writeBlobToHandle(fileHandle, blob) {
    const writable = await fileHandle.createWritable();
    await writable.write(blob);
    await writable.close();
}

function triggerBrowserDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function refreshPatientData() {
    if (!db) return;
    patientsData = [];
    try {
        const stmt = db.prepare('SELECT * FROM patient_assessments ORDER BY patient_name COLLATE NOCASE');
        let index = 0;
        while (stmt.step()) {
            const row = stmt.getAsObject();
            const normalized = normalizePatientRow(row, index);
            patientsData.push(normalized);
            index++;
        }
        stmt.free();
    } catch (error) {
        console.error(error);
        showStatus('Error reading database', 'error');
    }
    renderPatientTable();
    updateFilterCounts();
}

function normalizePatientRow(row, index) {
    const patient = { ...row };
    patient.created_by = row.created_by || '';
    patient.updated_by = row.updated_by || '';
    patient.created_at = row.created_at || '';
    patient.updated_at = row.updated_at || '';
    patient.entry_source = row.entry_source || (isTemporaryMrn(row.mrn) ? ENTRY_SOURCE_MANUAL : '');
    const legacyDeclined = Number(row.excl_declined) ? 1 : 0;
    INCLUSION_KEYS.concat(EXCLUSION_KEYS).forEach(key => {
        patient[key] = Number(patient[key]) ? 1 : 0;
    });
    const normalizedOptOut = normalizeOptOutStatus(row.opt_out_status, row.did_not_opt_out);
    let optStatus = normalizedOptOut;
    if (legacyDeclined && optStatus === OPT_OUT_STATUS.PENDING) {
        optStatus = OPT_OUT_STATUS.OPTED_OUT;
    }
    patient.opt_out_status = optStatus;
    patient.opt_out_date = normalizeISODateString(row.opt_out_date || '');
    patient.allocation = row.allocation || '';
    patient.study_id = normalizeStudyIdValue(row.study_id);
    patient.locked_at = row.locked_at || '';
    patient.locked_at = row.locked_at || '';
    patient.diabetes_known = Number(row.diabetes_known) ? 1 : 0;
    patient.location = patient.location || '';
    patient.location_at_notification = patient.location_at_notification || '';
    patient.location_at_randomization = patient.location_at_randomization || '';
    patient.therapy_prescribed = Number(patient.therapy_prescribed) ? 1 : 0;
    patient.did_not_opt_out = optStatus === OPT_OUT_STATUS.DID_NOT ? 1 : 0;
    patient.dialysis_duration_confirmed = Number(patient.dialysis_duration_confirmed) ? 1 : 0;
    patient.no_exclusions_confirmed = Number(row.no_exclusions_confirmed) ? 1 : 0;
    const hasRandomizedField = row.randomized !== undefined && row.randomized !== null;
    patient.randomized = Number(row.randomized) ? 1 : 0;
    patient.birth_date = normalizeISODateString(row.birth_date || '');
    const parsedBirth = parseISODate(patient.birth_date);
    if (parsedBirth) {
        const computedAge = calculateAgeFromDate(parsedBirth);
        patient.age = Number.isFinite(computedAge) ? computedAge : null;
    } else {
        const parsedAge = (patient.age === '' || patient.age === null || patient.age === undefined)
            ? NaN
            : Number(patient.age);
        patient.age = Number.isFinite(parsedAge) ? parsedAge : null;
    }
    patient.randomization_date = normalizeISODateString(patient.randomization_date || '');
    const enrollmentStatus = (patient.enrollment_status || '').toLowerCase();
    patient.notification_date = normalizeISODateString(patient.notification_date || '');
    patient.dialysis_start_date = normalizeISODateString(patient.dialysis_start_date || '');
    if (!hasRandomizedField && patient.randomization_date) {
        patient.randomized = 1;
    }
    if (!patient.randomized && patient.randomization_date && enrollmentStatus === 'enrolled') {
        patient.randomized = 1;
    }
    if (patient.randomized && enrollmentStatus !== 'enrolled') {
        patient.enrollment_status = 'enrolled';
    }
    patient._index = index;
    patient.health_card = patient.health_card || '';
    const provinceForHcn = patient.health_card_province || '';
    const locationInfo = getMostRecentLocationInfo(patient);
    patient.mostRecentLocationValue = locationInfo.value;
    patient.mostRecentLocationSource = locationInfo.source;
    patient.mostRecentLocationDisplay = formatLocationDisplay(locationInfo.value);
    patient.first_ready_date = computeFirstEligibleDate(patient);
    patient.first_ready_iso = patient.first_ready_date ? formatISODate(patient.first_ready_date) : '';
    patient.noExclusions = !legacyDeclined && EXCLUSION_KEYS.every(key => patient[key] === 0);
    patient.hasAnyExclusion = !patient.noExclusions;
    const needsDiabetesInfo = Number.isFinite(patient.age) && patient.age >= 45 && patient.age < 60;
    if (needsDiabetesInfo && patient.incl_age === 1) {
        patient.diabetes_known = 1;
    }
    if (Number.isFinite(patient.age)) {
        if (patient.age >= 60) {
            patient.incl_age = 1;
        } else if (patient.age >= 45 && patient.age < 60) {
            patient.incl_age = patient.diabetes_known ? 1 : 0;
        } else {
            patient.incl_age = 0;
        }
    }
    patient.hasHealthCard = patient.health_card.trim().length > 0;
    const hcnFormatError = validateHealthCardFormat(patient.health_card.trim(), provinceForHcn || '');
    patient.incl_health_card = patient.hasHealthCard && !hcnFormatError ? 1 : 0;
    patient.health_card_province = provinceForHcn || '';
    recalcDialysisInclusion(patient);
    patient.inclusionMet = INCLUSION_KEYS.every(key => patient[key] === 1);
    patient.bucketFlags = computeBucketFlags(patient);
    patient.primaryBucket = patient.bucketFlags.primary;
    patient.derivedStatus = patient.primaryBucket;
    patient.rowClass = rowClassFromStatus(patient);
    return patient;
}

function rowClassFromStatus(patient) {
    const flags = (patient && patient.bucketFlags) || {};
    if (flags.opted_out || flags.ineligible) return 'ineligible-row';
    if (flags.randomized_rx) return 'enrolled-row';
    if (flags.randomized_np || flags.ready_randomize || flags.ready_notify) return 'eligible-row';
    if (flags.waiting || flags.final_eligibility) return 'notified-row';
    if (flags.pending) return 'pending-row';
    if (flags.missing) return 'missing-row';
    return '';
}

const PRIMARY_BUCKET_ORDER = [
    'missing',
    'opted_out',
    'ineligible',
    'randomized_rx',
    'randomized_np',
    'ready_randomize',
    'final_eligibility',
    'waiting',
    'ready_notify',
    'pending'
];

function computeMissingEligibilityReasons(patient = {}) {
    const reasons = [];
    const ageValue = Number.isFinite(patient.age) ? patient.age : null;
    const needsDiabetesStatus = Number.isFinite(ageValue) && ageValue >= 45 && ageValue < 60;
    const hasHealthCard = Boolean((patient.health_card || '').trim());
    const hcnProvince = (patient.health_card_province || '').trim();
    const requiresDialysisUnit = patient.incl_incentre_hd === 1;
    const locationValue = requiresDialysisUnit ? getDialysisUnitCanonical(patient) : '';
    const hasDialysisUnit = requiresDialysisUnit && Boolean(normalizeLocationValue(locationValue));
    const hasDialysisHistory = Boolean(patient.dialysis_start_date) || Boolean(patient.dialysis_duration_confirmed);
    if (!Number.isFinite(ageValue)) reasons.push('Age missing');
    if (needsDiabetesStatus && Number(patient.diabetes_known) !== 1) reasons.push('Diabetes status missing (age 45-59)');
    if (!hasHealthCard) reasons.push('Health card number missing');
    if (hasHealthCard && !hcnProvince) reasons.push('HCN province/territory missing');
    const hcnFormatError = hasHealthCard ? validateHealthCardFormat(patient.health_card, hcnProvince || '') : '';
    if (hcnFormatError) reasons.push(hcnFormatError);
    if (requiresDialysisUnit && !hasDialysisUnit) reasons.push('Dialysis unit at randomization missing');
    if (!hasDialysisHistory) reasons.push('Dialysis start date or ≥90-day confirmation missing');
    return reasons;
}

function buildProvinceOptions(selected = '') {
    return Object.entries(PROVINCE_LABELS).map(([code, label]) => {
        const isSelected = code === selected ? 'selected' : '';
        const displayText = code === '' ? 'Province' : code;
        return `<option value="${code}" ${isSelected}>${displayText}</option>`;
    }).join('');
}

function mod10Check(value) {
    let sum = 0;
    const parity = value.length % 2;
    for (let i = 0; i < value.length; i++) {
        let digit = parseInt(value.charAt(i), 10);
        if (Number.isNaN(digit)) return false;
        if (i % 2 === parity) {
            digit *= 2;
            if (digit > 9) {
                digit -= 9;
            }
        }
        sum += digit;
    }
    return (sum % 10) === 0;
}

function validateHealthCardFormat(hcn, province) {
    if (!hcn) return '';
    if (!province) return 'Select province/territory to validate HCN.';
    const len = hcn.length;
    const isNumeric = /^[0-9]+$/.test(hcn);
    switch (province) {
        case 'AB':
        case 'NB':
        case 'SK':
        case 'YT':
            if (!(isNumeric && len === 9)) {
                return `${PROVINCE_LABELS[province]} HCN must be 9 digits.`;
            }
            break;
        case 'BC':
        case 'NS':
            if (!(isNumeric && len === 10)) {
                return `${PROVINCE_LABELS[province]} HCN must be 10 digits.`;
            }
            break;
        case 'ON':
            if (!(isNumeric && len === 10)) {
                return 'Ontario HCN must be 10 digits.';
            }
            if (!mod10Check(hcn)) {
                return 'Ontario HCN failed validity check.';
            }
            break;
        case 'MB':
            if (!(isNumeric && (len === 6 || len === 9))) {
                return 'Manitoba HCN must be 6 or 9 digits.';
            }
            break;
        case 'NL':
            if (!(isNumeric && len === 12)) {
                return 'Newfoundland and Labrador HCN must be 12 digits.';
            }
            break;
        case 'NT':
            if (!(/^[NDMT][0-9]{7}$/.test(hcn))) {
                return 'Northwest Territories HCN must start with N, D, M, or T followed by 7 digits (8 characters total).';
            }
            break;
        case 'NU':
            if (!(isNumeric && len === 9)) {
                return 'Nunavut HCN must be 9 digits.';
            }
            break;
        case 'PE':
            if (!(isNumeric && len === 8)) {
                return 'Prince Edward Island HCN must be 8 digits.';
            }
            break;
        case 'QC':
            if (!(/^[A-Z]{4}[0-9]{8}$/.test(hcn))) {
                return 'Quebec HCN must be 12 characters: 4 letters followed by 8 digits.';
            }
            break;
        default:
            return 'Select a valid province/territory to validate HCN.';
    }
    return '';
}
