const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITERATIONS = 100000;
const DATA_KEY_LEN = 32;
const PASSWORD_HASH_LEN = 32;
const ENCRYPTION_MAGIC = 'DIALEX-ENC-V2';
const ENCRYPTION_HEADER = `${ENCRYPTION_MAGIC}
`;
const MIN_PASSWORD_LENGTH = 8;
const PASSWORD_COMPLEXITY_REQUIRED_GROUPS = 3;
const USERNAME_PATTERN = /^[a-z0-9._-]{3,}$/i;
const STUDY_ID_PATTERN = /^[0-9]{4}-[A-Z]{3}-[0-9]{3}$/;
const TORONTO_TIME_ZONE = 'America/Toronto';
const TORONTO_PARTS_FORMATTER = new Intl.DateTimeFormat('en-CA', {
    timeZone: TORONTO_TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
});

let SQL;
let importedStudyIds = [];
let isSqlReady = false;
let isCreatingDatabase = false;

const statusEl = document.getElementById('status');
const createBtn = document.getElementById('create-btn');
const form = document.getElementById('provision-form');
const studyIdInput = document.getElementById('study-id-file');
const studyIdStatus = document.getElementById('study-id-status');
const studyIdPreview = document.getElementById('study-id-preview');
const clearStudyIdsBtn = document.getElementById('clear-study-ids');
const passwordToggle = document.getElementById('toggle-passwords');
const passwordFields = document.querySelectorAll('[data-password-field]');
const centralPasswordInput = document.getElementById('central-password');
const centralConfirmInput = document.getElementById('central-confirm');
const centralPasswordPolicyEl = document.getElementById('central-password-policy');
const adminUsernameInput = document.getElementById('admin-username');
const adminPasswordInput = document.getElementById('admin-password');
const adminConfirmInput = document.getElementById('admin-confirm');
const adminPasswordPolicyEl = document.getElementById('admin-password-policy');

function updateCreateButtonState() {
    createBtn.disabled = !isSqlReady || importedStudyIds.length === 0 || isCreatingDatabase;
}

function resetPasswordVisibilityToSecureDefault() {
    if (passwordToggle) {
        passwordToggle.checked = false;
    }
    passwordFields.forEach(field => {
        field.type = 'password';
    });
}

if (passwordToggle) {
    passwordToggle.addEventListener('change', () => {
        const nextType = passwordToggle.checked ? 'text' : 'password';
        passwordFields.forEach(field => {
            field.type = nextType;
        });
    });
}

resetPasswordVisibilityToSecureDefault();

function showStatus(message, type) {
    statusEl.textContent = message;
    statusEl.classList.remove('hidden', 'success', 'error');
    if (type) {
        statusEl.classList.add(type);
    }
}

function getTorontoDateParts(date = new Date()) {
    const parts = TORONTO_PARTS_FORMATTER.formatToParts(date);
    const values = {};
    parts.forEach(part => {
        if (part.type !== 'literal') {
            values[part.type] = part.value;
        }
    });
    return {
        year: Number(values.year),
        month: Number(values.month),
        day: Number(values.day),
        hour: Number(values.hour || 0),
        minute: Number(values.minute || 0),
        second: Number(values.second || 0)
    };
}

function getTorontoNow() {
    const parts = getTorontoDateParts();
    return new Date(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second, 0);
}

function formatTorontoFilenameTimestamp(date = getTorontoNow()) {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    const hh = String(date.getHours()).padStart(2, '0');
    const mm = String(date.getMinutes()).padStart(2, '0');
    const ss = String(date.getSeconds()).padStart(2, '0');
    return `${y}-${m}-${d}-${hh}-${mm}-${ss}`;
}

function formatTorontoSqlTimestamp(date = getTorontoNow()) {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    const hh = String(date.getHours()).padStart(2, '0');
    const mm = String(date.getMinutes()).padStart(2, '0');
    const ss = String(date.getSeconds()).padStart(2, '0');
    return `${y}-${m}-${d} ${hh}:${mm}:${ss}`;
}

function clearStatus() {
    statusEl.textContent = '';
    statusEl.classList.add('hidden');
    statusEl.classList.remove('success', 'error');
}

function normalizeUsername(value) {
    return (value || '').toString().trim().toLowerCase();
}

function getPasswordStrengthAssessment(password, options = {}) {
    const value = (password || '').toString();
    const hasLower = /[a-z]/.test(value);
    const hasUpper = /[A-Z]/.test(value);
    const hasNumber = /[0-9]/.test(value);
    const hasSymbol = /[^A-Za-z0-9]/.test(value);
    const groupCount = [hasLower, hasUpper, hasNumber, hasSymbol].filter(Boolean).length;
    const normalizedUsername = normalizeUsername(options.username || '');
    const containsUsername = Boolean(normalizedUsername) && value.toLowerCase().includes(normalizedUsername);
    return {
        hasMinLength: value.length >= MIN_PASSWORD_LENGTH,
        hasLower,
        hasUpper,
        hasNumber,
        hasSymbol,
        groupCount,
        hasRequiredGroups: groupCount >= PASSWORD_COMPLEXITY_REQUIRED_GROUPS,
        hasUsernameRule: Boolean(normalizedUsername),
        excludesUsername: !containsUsername
    };
}

function renderPasswordPolicyChecklist(container, options = {}) {
    if (!container) return;
    const password = (options.password || '').toString();
    const confirmation = (options.confirmation || '').toString();
    const assessmentPassword = password || confirmation;
    const assessment = getPasswordStrengthAssessment(assessmentPassword, { username: options.username || '' });
    const confirmationMatches = confirmation.length > 0 && confirmation === password;
    const checks = [
        { passed: assessment.hasMinLength, label: `At least ${MIN_PASSWORD_LENGTH} characters` },
        { passed: assessment.hasLower, label: 'Contains lowercase letter (a-z)' },
        { passed: assessment.hasUpper, label: 'Contains uppercase letter (A-Z)' },
        { passed: assessment.hasNumber, label: 'Contains number (0-9)' },
        { passed: assessment.hasSymbol, label: 'Contains symbol (for example: !, @, #)' },
        {
            passed: assessment.hasRequiredGroups,
            label: `Meets at least ${PASSWORD_COMPLEXITY_REQUIRED_GROUPS} of 4 character types (${assessment.groupCount}/4)`
        }
    ];
    if (assessment.hasUsernameRule) {
        checks.push({ passed: assessment.excludesUsername, label: 'Does not contain username' });
    }
    checks.push({ passed: confirmationMatches, label: 'Password and confirmation match' });

    container.innerHTML = `
        <div class="password-policy-title">Password requirements</div>
        <ul class="password-policy-list">
            ${checks.map(check => `
                <li class="password-policy-item ${check.passed ? 'pass' : 'fail'}">
                    <span class="password-policy-indicator">${check.passed ? 'Pass' : 'Missing'}</span>
                    <span class="password-policy-text">${check.label}</span>
                </li>
            `).join('')}
        </ul>
    `;
}

function validatePasswordStrength(password, options = {}) {
    const label = options.label || 'Password';
    const assessment = getPasswordStrengthAssessment(password, options);
    if (!assessment.hasMinLength) {
        return `${label} must be at least ${MIN_PASSWORD_LENGTH} characters.`;
    }
    if (!assessment.hasRequiredGroups) {
        return `${label} must include at least 3 of the following: uppercase letters, lowercase letters, numbers, symbols.`;
    }
    if (assessment.hasUsernameRule && !assessment.excludesUsername) {
        return `${label} must not contain the username.`;
    }
    return '';
}

function refreshPasswordPolicyChecklist() {
    renderPasswordPolicyChecklist(centralPasswordPolicyEl, {
        password: centralPasswordInput ? centralPasswordInput.value : '',
        confirmation: centralConfirmInput ? centralConfirmInput.value : '',
        username: ''
    });
    renderPasswordPolicyChecklist(adminPasswordPolicyEl, {
        password: adminPasswordInput ? adminPasswordInput.value : '',
        confirmation: adminConfirmInput ? adminConfirmInput.value : '',
        username: adminUsernameInput ? adminUsernameInput.value : ''
    });
}

function getUserWrapId(username) {
    const normalized = normalizeUsername(username);
    return normalized ? `user:${normalized}` : '';
}

function sanitizeFileLabel(value) {
    const trimmed = (value || '').trim().toLowerCase();
    if (!trimmed) return '';
    return trimmed.replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
}

function setStudyIdStatus(message, type) {
    studyIdStatus.textContent = message;
    studyIdStatus.classList.remove('success', 'error');
    if (type) {
        studyIdStatus.classList.add(type);
    }
}

function normalizeStudyIdValue(value) {
    return (value || '').toString().trim().toUpperCase();
}

function normalizeHeaderValue(value) {
    return (value || '').toString().replace(/^\uFEFF/, '').trim().toLowerCase();
}

function detectDelimiter(text) {
    const lines = text.split(/\r?\n/);
    const sample = lines.find(line => line.trim());
    if (!sample) return ',';
    const commaCount = (sample.match(/,/g) || []).length;
    const tabCount = (sample.match(/\t/g) || []).length;
    return tabCount > commaCount ? '\t' : ',';
}

function parseDelimitedRows(text, delimiter) {
    const rows = [];
    let row = [];
    let cell = '';
    let inQuotes = false;

    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        if (inQuotes) {
            if (char === '"') {
                const nextChar = text[i + 1];
                if (nextChar === '"') {
                    cell += '"';
                    i += 1;
                } else {
                    inQuotes = false;
                }
            } else {
                cell += char;
            }
            continue;
        }
        if (char === '"') {
            inQuotes = true;
            continue;
        }
        if (char === delimiter) {
            row.push(cell);
            cell = '';
            continue;
        }
        if (char === '\n') {
            row.push(cell);
            rows.push(row);
            row = [];
            cell = '';
            continue;
        }
        if (char === '\r') {
            continue;
        }
        cell += char;
    }

    row.push(cell);
    rows.push(row);

    while (rows.length && rows[rows.length - 1].every(value => value === '')) {
        rows.pop();
    }

    return rows;
}

function extractStudyIdsFromRows(rows) {
    if (!rows.length) {
        return { error: 'CSV appears to be empty.' };
    }

    const header = rows[0].map(normalizeHeaderValue);
    let idIndex = header.indexOf('study_id');
    let startRow = 0;

    if (idIndex !== -1) {
        startRow = 1;
    } else if (header.length === 1) {
        idIndex = 0;
    } else {
        return { error: 'CSV must include a study_id column.' };
    }

    const ids = [];
    const seen = new Set();
    let invalidCount = 0;
    let duplicateCount = 0;

    for (let i = startRow; i < rows.length; i++) {
        const row = rows[i] || [];
        const rawValue = row[idIndex];
        const normalized = normalizeStudyIdValue(rawValue);
        if (!normalized) continue;
        if (!STUDY_ID_PATTERN.test(normalized)) {
            invalidCount += 1;
            continue;
        }
        if (seen.has(normalized)) {
            duplicateCount += 1;
            continue;
        }
        seen.add(normalized);
        ids.push(normalized);
    }

    if (!ids.length) {
        return { error: 'No valid study IDs found in the CSV.' };
    }

    return { ids, invalidCount, duplicateCount };
}

function renderStudyIdPreview(ids) {
    if (!ids.length) {
        studyIdPreview.textContent = '';
        studyIdPreview.classList.add('hidden');
        return;
    }
    const preview = ids.slice(0, 6).join(', ');
    const remainder = ids.length > 6 ? ` +${ids.length - 6} more` : '';
    studyIdPreview.textContent = `Example IDs: ${preview}${remainder}`;
    studyIdPreview.classList.remove('hidden');
}

function clearStudyIdImport() {
    importedStudyIds = [];
    studyIdInput.value = '';
    setStudyIdStatus('Study ID list required. Import a CSV to continue.');
    studyIdPreview.textContent = '';
    studyIdPreview.classList.add('hidden');
    clearStudyIdsBtn.disabled = true;
    updateCreateButtonState();
}

function handleStudyIdFileChange(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) {
        clearStudyIdImport();
        return;
    }

    setStudyIdStatus('Reading CSV...');
    const reader = new FileReader();
    reader.onload = () => {
        const text = (reader.result || '').toString();
        const delimiter = detectDelimiter(text);
        const rows = parseDelimitedRows(text, delimiter);
        const result = extractStudyIdsFromRows(rows);
        if (result.error) {
            importedStudyIds = [];
            clearStudyIdsBtn.disabled = true;
            renderStudyIdPreview([]);
            setStudyIdStatus(result.error, 'error');
            updateCreateButtonState();
            return;
        }

        importedStudyIds = result.ids;
        clearStudyIdsBtn.disabled = importedStudyIds.length === 0;
        let message = `Loaded ${importedStudyIds.length} study IDs from ${file.name || 'CSV file'}.`;
        if (result.invalidCount) {
            message += ` Skipped ${result.invalidCount} invalid entries.`;
        }
        if (result.duplicateCount) {
            message += ` Skipped ${result.duplicateCount} duplicates.`;
        }
        setStudyIdStatus(message, 'success');
        renderStudyIdPreview(importedStudyIds);
        updateCreateButtonState();
    };
    reader.onerror = () => {
        importedStudyIds = [];
        clearStudyIdsBtn.disabled = true;
        renderStudyIdPreview([]);
        setStudyIdStatus('Unable to read the CSV file.', 'error');
        updateCreateButtonState();
    };
    reader.readAsText(file);
}

function hasScriptTagForSource(src) {
    const expected = new URL(src, window.location.href).href;
    return Array.from(document.scripts).some(script => script.src === expected);
}

function loadScriptSource(src) {
    return new Promise((resolve, reject) => {
        if (hasScriptTagForSource(src) && typeof initSqlJs === 'function') {
            resolve();
            return;
        }
        const script = document.createElement('script');
        script.src = src;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error(`Unable to load ${src}`));
        document.head.appendChild(script);
    });
}

async function ensureSqlJsLoaded() {
    if (typeof initSqlJs === 'function') {
        return true;
    }
    const candidateSources = [
        'js/lib/sql.js',
        '../DIALEX_Recruitment_Tracker/js/lib/sql.js'
    ];
    for (const src of candidateSources) {
        try {
            await loadScriptSource(src);
            if (typeof initSqlJs === 'function') {
                return true;
            }
        } catch (error) {
            console.warn(error.message);
        }
    }
    return false;
}

async function getPasswordKey(password) {
    const enc = new TextEncoder();
    return window.crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey', 'deriveBits']
    );
}

async function deriveKey(passwordKey, salt, keyUsage) {
    return window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        keyUsage
    );
}

function bytesToBase64(bytes) {
    let binary = '';
    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });
    return btoa(binary);
}

function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

async function derivePasswordHash(password, salt) {
    const passwordKey = await getPasswordKey(password);
    const bits = await window.crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        passwordKey,
        PASSWORD_HASH_LEN * 8
    );
    return new Uint8Array(bits);
}

async function createPasswordRecord(password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const hash = await derivePasswordHash(password, salt);
    return {
        salt: bytesToBase64(salt),
        hash: bytesToBase64(hash)
    };
}

async function generateDataKey() {
    return window.crypto.getRandomValues(new Uint8Array(DATA_KEY_LEN));
}

async function importAesKey(rawBytes, usage) {
    return window.crypto.subtle.importKey(
        'raw',
        rawBytes,
        { name: 'AES-GCM' },
        false,
        usage
    );
}

async function wrapDataKey(dataKeyBytes, password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LEN));
    const passwordKey = await getPasswordKey(password);
    const aesKey = await deriveKey(passwordKey, salt, ['encrypt']);
    const wrapped = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, dataKeyBytes);
    return {
        salt: bytesToBase64(salt),
        iv: bytesToBase64(iv),
        wrapped: bytesToBase64(new Uint8Array(wrapped)),
        iterations: PBKDF2_ITERATIONS
    };
}

function serializeEncryptedPayloadV2(payload) {
    const text = `${ENCRYPTION_HEADER}${JSON.stringify(payload)}`;
    return new TextEncoder().encode(text);
}

async function encryptDatabaseV2(dataBytes, encryptionState) {
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LEN));
    const aesKey = await importAesKey(encryptionState.dataKey, ['encrypt']);
    const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, dataBytes);
    const payload = {
        format: ENCRYPTION_MAGIC,
        version: 2,
        wraps: encryptionState.wraps,
        data: {
            iv: bytesToBase64(iv),
            ciphertext: bytesToBase64(new Uint8Array(encrypted))
        }
    };
    return serializeEncryptedPayloadV2(payload);
}

async function createEncryptionState(centralPassword, userWraps) {
    const dataKey = await generateDataKey();
    const wraps = [];
    wraps.push({ id: 'central', ...(await wrapDataKey(dataKey, centralPassword)) });
    for (const entry of userWraps || []) {
        if (!entry || !entry.id || !entry.password) continue;
        wraps.push({ id: entry.id, ...(await wrapDataKey(dataKey, entry.password)) });
    }
    return {
        mode: 'multi',
        dataKey,
        wraps,
        unlockId: 'central'
    };
}

function setupDatabase(db) {
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
            created_by TEXT,
            updated_by TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    db.run(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_patient_study_id_unique
        ON patient_assessments(study_id)
        WHERE TRIM(COALESCE(study_id, '')) <> ''
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
            failed_attempts INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0,
            locked_until INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS study_ids (
            study_id TEXT PRIMARY KEY,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
}

function insertAdminUser(db, username, firstName, lastName, passwordRecord) {
    const displayName = buildDisplayName(firstName, lastName);
    const timestamp = formatTorontoSqlTimestamp();
    const stmt = db.prepare(`
        INSERT INTO users (username, display_name, password_salt, password_hash, role, active, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'admin', 1, ?, ?)
    `);
    stmt.run([username, displayName, passwordRecord.salt, passwordRecord.hash, timestamp, timestamp]);
    stmt.free();
}

function insertStudyIds(db, studyIds) {
    if (!studyIds || !studyIds.length) return;
    const stmt = db.prepare(`INSERT INTO study_ids (study_id, created_at) VALUES (?, ?)`);
    const timestamp = formatTorontoSqlTimestamp();
    db.run('BEGIN');
    try {
        studyIds.forEach(studyId => {
            stmt.run([studyId, timestamp]);
        });
        db.run('COMMIT');
    } catch (error) {
        db.run('ROLLBACK');
        throw error;
    } finally {
        stmt.free();
    }
}

function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function buildFilename(siteLabel) {
    const timestamp = formatTorontoFilenameTimestamp();
    const base = siteLabel ? `dialex-${siteLabel}-initial` : 'dialex-site-initial';
    return `${base}-${timestamp}.enc`;
}

function validatePasswords(label, password, confirmation, options = {}) {
    const policyError = validatePasswordStrength(password, { label, username: options.username || '' });
    if (policyError) {
        return policyError;
    }
    if (password !== confirmation) {
        return `${label} values do not match.`;
    }
    return '';
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

async function handleProvision(event) {
    event.preventDefault();
    clearStatus();

    const centralPassword = document.getElementById('central-password').value;
    const centralConfirm = document.getElementById('central-confirm').value;
    const adminUsernameRaw = document.getElementById('admin-username').value;
    const adminFirstNameRaw = document.getElementById('admin-first-name').value;
    const adminLastNameRaw = document.getElementById('admin-last-name').value;
    const adminPassword = document.getElementById('admin-password').value;
    const adminConfirm = document.getElementById('admin-confirm').value;
    const siteLabelRaw = document.getElementById('site-label').value;

    const adminUsername = normalizeUsername(adminUsernameRaw);
    if (!adminUsername || !USERNAME_PATTERN.test(adminUsername)) {
        showStatus('Enter a valid admin username (letters, numbers, dot, underscore, dash).', 'error');
        return;
    }

    const adminFirstName = normalizeNamePart(adminFirstNameRaw);
    const adminLastName = normalizeNamePart(adminLastNameRaw);
    if (!hasRequiredNameParts(adminFirstName, adminLastName)) {
        showStatus('Enter both first name and last name for the admin account.', 'error');
        return;
    }

    const centralError = validatePasswords('Central recovery password', centralPassword, centralConfirm);
    if (centralError) {
        showStatus(centralError, 'error');
        return;
    }

    const adminError = validatePasswords('Admin password', adminPassword, adminConfirm, { username: adminUsername });
    if (adminError) {
        showStatus(adminError, 'error');
        return;
    }

    if (!importedStudyIds.length) {
        showStatus('Import a study ID CSV before creating the database.', 'error');
        studyIdInput.focus();
        return;
    }

    if (!isSqlReady) {
        showStatus('Database engine is not ready yet. Wait for initialization and try again.', 'error');
        return;
    }

    isCreatingDatabase = true;
    updateCreateButtonState();

    try {
        const db = new SQL.Database();
        setupDatabase(db);
        const adminRecord = await createPasswordRecord(adminPassword);
        insertAdminUser(db, adminUsername, adminFirstName, adminLastName, adminRecord);
        insertStudyIds(db, importedStudyIds);

        const sqlData = db.export();
        const adminWrapId = getUserWrapId(adminUsername);
        const encryptionState = await createEncryptionState(centralPassword, [
            { id: adminWrapId, password: adminPassword }
        ]);
        const encrypted = await encryptDatabaseV2(sqlData, encryptionState);
        const siteLabel = sanitizeFileLabel(siteLabelRaw);
        const filename = buildFilename(siteLabel);
        const blob = new Blob([encrypted], { type: 'application/octet-stream' });
        triggerDownload(blob, filename);

        showStatus(`Encrypted starter database created. Keep the central recovery password private and share the admin credentials with the site. Included ${importedStudyIds.length} study IDs.`, 'success');
        form.reset();
        resetPasswordVisibilityToSecureDefault();
        refreshPasswordPolicyChecklist();
        clearStudyIdImport();
    } catch (error) {
        console.error(error);
        showStatus(error.message || 'Unable to create database.', 'error');
    } finally {
        isCreatingDatabase = false;
        updateCreateButtonState();
    }
}

form.addEventListener('submit', handleProvision);
studyIdInput.addEventListener('change', handleStudyIdFileChange);
clearStudyIdsBtn.addEventListener('click', clearStudyIdImport);
if (centralPasswordInput) centralPasswordInput.addEventListener('input', refreshPasswordPolicyChecklist);
if (centralPasswordInput) centralPasswordInput.addEventListener('change', refreshPasswordPolicyChecklist);
if (centralConfirmInput) centralConfirmInput.addEventListener('input', refreshPasswordPolicyChecklist);
if (centralConfirmInput) centralConfirmInput.addEventListener('change', refreshPasswordPolicyChecklist);
if (adminUsernameInput) adminUsernameInput.addEventListener('input', refreshPasswordPolicyChecklist);
if (adminUsernameInput) adminUsernameInput.addEventListener('change', refreshPasswordPolicyChecklist);
if (adminPasswordInput) adminPasswordInput.addEventListener('input', refreshPasswordPolicyChecklist);
if (adminPasswordInput) adminPasswordInput.addEventListener('change', refreshPasswordPolicyChecklist);
if (adminConfirmInput) adminConfirmInput.addEventListener('input', refreshPasswordPolicyChecklist);
if (adminConfirmInput) adminConfirmInput.addEventListener('change', refreshPasswordPolicyChecklist);

async function initializeSqlEngine() {
    const hasSqlJs = await ensureSqlJsLoaded();
    if (!hasSqlJs) {
        showStatus('Unable to initialize database engine: sql.js was not found. Keep this folder with the full DIALEX package.', 'error');
        return;
    }

    try {
        SQL = await initSqlJs();
        isSqlReady = true;
        updateCreateButtonState();
        showStatus('Ready to create a site starter database.', 'success');
    } catch (error) {
        console.error(error);
        showStatus('Unable to initialize database engine.', 'error');
    }
}

updateCreateButtonState();
refreshPasswordPolicyChecklist();
initializeSqlEngine();
