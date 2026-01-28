// --- CRYPTO UTILITIES START ---
const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITERATIONS = 100000;
const DATA_KEY_LEN = 32;
const PASSWORD_HASH_LEN = 32;
const ENCRYPTION_MAGIC = 'DIALEX-ENC-V2';
const ENCRYPTION_HEADER = `${ENCRYPTION_MAGIC}\n`;
const MIN_PASSWORD_LENGTH = 8;
const USERNAME_PATTERN = /^[a-z0-9._-]{3,}$/i;

async function getPasswordKey(password) {
    const enc = new TextEncoder();
    return window.crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey", "deriveBits"]);
}

async function deriveKey(passwordKey, salt, keyUsage) {
    return window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        false,
        keyUsage
    );
}

async function encryptData(dataBytes, password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LEN));
    const passwordKey = await getPasswordKey(password);
    const aesKey = await deriveKey(passwordKey, salt, ["encrypt"]);
    const encryptedContent = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, dataBytes);

    const encryptedBytes = new Uint8Array(encryptedContent);
    const result = new Uint8Array(salt.length + iv.length + encryptedBytes.length);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(encryptedBytes, salt.length + iv.length);
    return result;
}

async function decryptData(packedData, password) {
    const salt = packedData.slice(0, SALT_LEN);
    const iv = packedData.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const encryptedBytes = packedData.slice(SALT_LEN + IV_LEN);
    const passwordKey = await getPasswordKey(password);
    const aesKey = await deriveKey(passwordKey, salt, ["decrypt"]);
    try {
        const decryptedContent = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, encryptedBytes);
        return new Uint8Array(decryptedContent);
    } catch (e) {
        throw new Error("Incorrect password or corrupted file.");
    }
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

function isV2EncryptedPayload(bytes) {
    if (!bytes || bytes.length < ENCRYPTION_HEADER.length) return false;
    const headerBytes = bytes.slice(0, ENCRYPTION_HEADER.length);
    const headerText = new TextDecoder().decode(headerBytes);
    return headerText === ENCRYPTION_HEADER;
}

function parseEncryptedPayloadV2(bytes) {
    const text = new TextDecoder().decode(bytes);
    if (!text.startsWith(ENCRYPTION_HEADER)) return null;
    const jsonText = text.slice(ENCRYPTION_HEADER.length);
    return JSON.parse(jsonText);
}

function serializeEncryptedPayloadV2(payload) {
    const text = `${ENCRYPTION_HEADER}${JSON.stringify(payload)}`;
    return new TextEncoder().encode(text);
}

async function generateDataKey() {
    return window.crypto.getRandomValues(new Uint8Array(DATA_KEY_LEN));
}

async function importAesKey(rawBytes, usage) {
    return window.crypto.subtle.importKey(
        "raw",
        rawBytes,
        { name: "AES-GCM" },
        false,
        usage
    );
}

async function wrapDataKey(dataKeyBytes, password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LEN));
    const passwordKey = await getPasswordKey(password);
    const aesKey = await deriveKey(passwordKey, salt, ["encrypt"]);
    const wrapped = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, dataKeyBytes);
    return {
        salt: bytesToBase64(salt),
        iv: bytesToBase64(iv),
        wrapped: bytesToBase64(new Uint8Array(wrapped)),
        iterations: PBKDF2_ITERATIONS
    };
}

function getUserWrapId(username) {
    const normalized = normalizeUsername(username);
    return normalized ? `user:${normalized}` : '';
}

async function upsertUserWrap(username, password) {
    if (!encryptionState || encryptionState.mode !== 'multi' || !encryptionState.dataKey) return false;
    const wrapId = getUserWrapId(username);
    if (!wrapId) return false;
    const wraps = Array.isArray(encryptionState.wraps) ? encryptionState.wraps : [];
    const newWrap = await wrapDataKey(encryptionState.dataKey, password);
    const updated = { id: wrapId, ...newWrap };
    const index = wraps.findIndex(entry => entry.id === wrapId);
    if (index >= 0) {
        wraps[index] = updated;
    } else {
        wraps.push(updated);
    }
    encryptionState.wraps = wraps;
    return true;
}

function removeUserWrap(username) {
    if (!encryptionState || encryptionState.mode !== 'multi' || !Array.isArray(encryptionState.wraps)) return false;
    const wrapId = getUserWrapId(username);
    if (!wrapId) return false;
    const nextWraps = encryptionState.wraps.filter(entry => entry.id !== wrapId);
    if (nextWraps.length === encryptionState.wraps.length) return false;
    encryptionState.wraps = nextWraps;
    return true;
}

async function unwrapDataKey(password, wrapEntry) {
    const salt = base64ToBytes(wrapEntry.salt);
    const iv = base64ToBytes(wrapEntry.iv);
    const wrapped = base64ToBytes(wrapEntry.wrapped);
    const passwordKey = await getPasswordKey(password);
    const aesKey = await deriveKey(passwordKey, salt, ["decrypt"]);
    const rawKey = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, wrapped);
    return new Uint8Array(rawKey);
}

async function findDataKeyForPassword(password, wraps = [], options = {}) {
    const wrapId = options && options.wrapId ? options.wrapId : '';
    const candidates = wrapId
        ? wraps.filter(entry => entry && entry.id === wrapId)
        : wraps;
    for (const wrapEntry of candidates) {
        try {
            const dataKey = await unwrapDataKey(password, wrapEntry);
            return { dataKey, unlockId: wrapEntry.id || '' };
        } catch (error) {
            // continue searching
        }
    }
    throw new Error("Incorrect password or corrupted file.");
}

async function encryptDatabaseV2(dataBytes, encryptionState) {
    if (!encryptionState || !encryptionState.dataKey) {
        throw new Error("Missing encryption state.");
    }
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LEN));
    const aesKey = await importAesKey(encryptionState.dataKey, ["encrypt"]);
    const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, dataBytes);
    const payload = {
        format: ENCRYPTION_MAGIC,
        version: 2,
        wraps: encryptionState.wraps || [],
        data: {
            iv: bytesToBase64(iv),
            ciphertext: bytesToBase64(new Uint8Array(encrypted))
        }
    };
    return serializeEncryptedPayloadV2(payload);
}

async function decryptDatabaseV2(bytes, password, options = {}) {
    const payload = parseEncryptedPayloadV2(bytes);
    if (!payload || !Array.isArray(payload.wraps)) {
        throw new Error("Invalid encrypted file format.");
    }
    const { dataKey, unlockId } = await findDataKeyForPassword(password, payload.wraps, options);
    const dataIv = base64ToBytes(payload.data.iv);
    const ciphertext = base64ToBytes(payload.data.ciphertext);
    const aesKey = await importAesKey(dataKey, ["decrypt"]);
    const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: dataIv }, aesKey, ciphertext);
    return {
        dataBytes: new Uint8Array(decrypted),
        encryptionState: {
            mode: 'multi',
            dataKey,
            wraps: payload.wraps,
            unlockId: unlockId || ''
        }
    };
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

async function decryptDatabasePayload(packedData, password, options = {}) {
    if (!isV2EncryptedPayload(packedData)) {
        throw new Error('Legacy encrypted databases are no longer supported.');
    }
    return await decryptDatabaseV2(packedData, password, options);
}

async function ensureEncryptionStateForSave() {
    if (encryptionState && encryptionState.mode === 'multi') {
        if (!encryptionState.dataKey || !Array.isArray(encryptionState.wraps) || !encryptionState.wraps.length) {
            showStatus('Encryption metadata is missing. Reload the database.', 'error');
            return false;
        }
        return true;
    }
    if (!currentUser || !currentUser.username) {
        showStatus('Sign in to save the database.', 'error');
        return false;
    }

    const needsUpgrade = Boolean(encryptionState && encryptionState.mode === 'legacy');
    let accountPassword = await promptPasswordModal({
        title: needsUpgrade ? 'Upgrade encryption' : 'Confirm account password',
        message: needsUpgrade
            ? 'This database uses legacy encryption. Enter your account password to upgrade it to multi-user encryption to enable continuous data saving.'
            : 'Enter your account password so your account can unlock this database.',
        requireConfirmation: false,
        submitLabel: 'Continue',
        autocomplete: 'current-password'
    });
    if (!accountPassword) return false;

    const currentRecord = fetchUserByUsername(normalizeUsername(currentUser.username));
    if (!currentRecord) {
        showStatus('Unable to confirm the current account.', 'error');
        return false;
    }
    const valid = await verifyPassword(accountPassword, currentRecord.password_salt, currentRecord.password_hash);
    if (!valid) {
        showStatus('Incorrect account password.', 'error');
        return false;
    }

    let centralPassword = await promptPasswordModal({
        title: 'Set central recovery password',
        message: needsUpgrade
            ? 'Create and confirm the central recovery password for the upgraded database. Other users will need to sign in again after the upgrade.'
            : 'Create and confirm the central password used for recovery if user passwords are lost.',
        requireConfirmation: true,
        submitLabel: 'Continue',
        autocomplete: 'new-password',
        minLength: MIN_PASSWORD_LENGTH
    });
    if (!centralPassword) return false;

    encryptionState = await createEncryptionState(centralPassword, [
        { id: getUserWrapId(currentUser.username), password: accountPassword }
    ]);
    accountPassword = null;
    centralPassword = null;
    return true;
}

async function derivePasswordHash(password, salt) {
    const passwordKey = await getPasswordKey(password);
    const bits = await window.crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
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

function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

async function verifyPassword(password, saltBase64, hashBase64) {
    const salt = base64ToBytes(saltBase64);
    const expected = base64ToBytes(hashBase64);
    const actual = await derivePasswordHash(password, salt);
    return constantTimeEqual(actual, expected);
}
// --- CRYPTO UTILITIES END ---

const INCLUSION_KEYS = ['incl_age', 'incl_dialysis_90d', 'incl_incentre_hd', 'incl_health_card'];
const INCLUSION_FIELD_MAP = {
    incl_age: ['age', 'diabetes_status'],
    incl_dialysis_90d: ['dialysis_start_date'],
    incl_incentre_hd: ['dialysis_unit'],
    incl_health_card: ['health_card', 'health_card_province']
};
const INCLUSION_FIELD_LIST = Object.values(INCLUSION_FIELD_MAP)
    .reduce((acc, fields) => acc.concat(fields), []);
const INCLUSION_FIELD_MESSAGES = {
    incl_age: 'Update age or diabetes status to recalculate the age criterion.',
    incl_dialysis_90d: 'Update the dialysis start date or ≥90-day confirmation.',
    incl_incentre_hd: 'Update the dialysis unit selection to reflect in-centre HD.',
    incl_health_card: 'Update the health card number and province/territory.'
};
const FIELD_HIGHLIGHT_DURATION = 1800;
const EXCLUSION_KEYS = [
    'excl_hd_less3', 'excl_intolerance', 'excl_hdf_planned', 'excl_nocturnal',
    'excl_discontinue', 'excl_nonadherence', 'excl_preference', 'excl_other_medical',
    'excl_other_trial', 'excl_previous'
];
const FILTERS = [
    { key: 'all', buttonId: 'show-all-btn', countId: 'count-all' },
    { key: 'missing', buttonId: 'show-missing-btn', countId: 'count-missing' },
    { key: 'pending', buttonId: 'show-pending-btn', countId: 'count-pending' },
    { key: 'ready_notify', buttonId: 'show-notify-btn', countId: 'count-ready-notify' },
    { key: 'waiting', buttonId: 'show-waiting-btn', countId: 'count-waiting' },
    { key: 'final_eligibility', buttonId: 'show-final-btn', countId: 'count-final' },
    { key: 'ready_randomize', buttonId: 'show-ready-btn', countId: 'count-ready' },
    { key: 'randomized_np', buttonId: 'show-randomized-np-btn', countId: 'count-randomized-np' },
    { key: 'randomized_rx', buttonId: 'show-prescribed-btn', countId: 'count-prescribed' },
    { key: 'ineligible', buttonId: 'show-ineligible-btn', countId: 'count-ineligible' },
    { key: 'opted_out', buttonId: 'show-optedout-btn', countId: 'count-optedout' },
    { key: 'notes', buttonId: 'show-notes-btn', countId: 'count-notes' }
];
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const NOTIFICATION_BUFFER_DAYS = 15;
const MIN_DIALYSIS_DAYS = 90;
const OPT_OUT_STATUS = {
    PENDING: 'pending',
    DID_NOT: 'did_not_opt_out',
    OPTED_OUT: 'opted_out'
};
const STUDY_ID_REGEX = /^\d{4}-[A-Z]{3}-\d{3}$/;
const READ_ONLY_MESSAGE = 'Record is locked; only notes remain editable.';
const TEMP_MRN_PREFIX = '__pending_patient__';
const ENTRY_SOURCE_MANUAL = 'manual';
const ENTRY_SOURCE_IMPORT = 'import';
const PROVINCE_LABELS = {
    '': 'Select province/territory',
    AB: 'Alberta',
    BC: 'British Columbia',
    MB: 'Manitoba',
    NB: 'New Brunswick',
    NL: 'Newfoundland and Labrador',
    NS: 'Nova Scotia',
    NT: 'Northwest Territories',
    NU: 'Nunavut',
    ON: 'Ontario',
    PE: 'Prince Edward Island',
    QC: 'Quebec',
    SK: 'Saskatchewan',
    YT: 'Yukon'
};

const HEADERS_LINE_INDEX = 1;
const FIRST_DATA_LINE_INDEX = 2;
const LOCATION_HEADER = "Location";
const LAST_HCN_HEADER = "Last Known Health Card Number";
const HCN_PROVINCE_HEADER = "Province of Healthcard No.";
const MRN_HEADER = "MRN";
const HCN_HEADER = "Healthcard Number";
const BIRTH_DATE_HEADER = "Patient Date of Birth DD/MM/YYYY";
const START_DATE_HEADER = "Dialysis Start Date DD/MM/YYYY";
const MODALITY_HEADER = "Modality";
const DIAB_TYPE1_HEADER = "Diabetes Type I?";
const DIAB_TYPE2_HEADER = "Diabetes Type II?";

const DIABETES_STATUS = {
    UNKNOWN: 0,
    NO: -1,
    YES: 1
};

function normalizeDiabetesStatus(value) {
    const num = Number(value);
    if (num === DIABETES_STATUS.YES) return DIABETES_STATUS.YES;
    if (num === DIABETES_STATUS.NO) return DIABETES_STATUS.NO;
    return DIABETES_STATUS.UNKNOWN;
}

function parseDiabetesField(value) {
    if (value === null || value === undefined) return DIABETES_STATUS.UNKNOWN;
    const normalized = String(value).trim().toLowerCase();
    if (!normalized) return DIABETES_STATUS.UNKNOWN;
    if (['yes', 'true', '1', 'y'].includes(normalized)) return DIABETES_STATUS.YES;
    if (['no', 'false', '0', 'n'].includes(normalized)) return DIABETES_STATUS.NO;
    if (['unknown', 'unk', 'u', 'na', 'n/a'].includes(normalized)) return DIABETES_STATUS.UNKNOWN;
    return DIABETES_STATUS.UNKNOWN;
}

function resolveDiabetesStatus(type1Value, type2Value) {
    const statuses = [parseDiabetesField(type1Value), parseDiabetesField(type2Value)];
    if (statuses.includes(DIABETES_STATUS.YES)) return DIABETES_STATUS.YES;
    const hasKnownNo = statuses.includes(DIABETES_STATUS.NO);
    const hasUnknown = statuses.includes(DIABETES_STATUS.UNKNOWN);
    if (hasKnownNo && !hasUnknown) return DIABETES_STATUS.NO;
    return DIABETES_STATUS.UNKNOWN;
}

const VALID_MODALITY_CODES = ['111', '121', '211', '221', '311', '321'];

const VALID_MODALITIES = {
    '111': 'Acute Care Hospital - Conventional HD - Total Care',
    '121': 'Acute Care Hospital - Short Daily HD - Total Care',
    '211': 'Chronic Care Hospital - Conventional - Total Care',
    '221': 'Chronic Care Hospital - Short Daily HD - Total Care',
    '311': 'Community Centre - Conventional HD - Total Care',
    '321': 'Community Centre - Short Daily HD - Total Care'
};

const DISPLAY_MODALITIES = {
    'Acute Care Hospital - Conventional HD - Total Care': 'Conventional HD',
    'Acute Care Hospital - Short Daily HD - Total Care': 'Short Daily HD',
    'Chronic Care Hospital - Conventional - Total Care': 'Conventional HD',
    'Chronic Care Hospital - Short Daily HD - Total Care': 'Short Daily HD',
    'Community Centre - Conventional HD - Total Care': 'Conventional HD',
    'Community Centre - Short Daily HD - Total Care': 'Short Daily HD',
};

const DISPLAY_TO_PREFERRED_CODE = (() => {
    const mapping = {};
    Object.entries(VALID_MODALITIES).forEach(([code, fullName]) => {
        const display = DISPLAY_MODALITIES[fullName];
        if (display && !mapping[display]) {
            mapping[display] = code;
        }
    });
    return mapping;
})();

const LOCATION_CODES = {
    "ALL": "STEVENSON MEMORIAL (ALLISTON)",
    "ALS": "ADAM LINTON DIALYSIS UNIT",
    "AMG": "ALEXANDRA MARINE AND GENERAL HOSPITAL - GODERICH",
    "BCC": "BRUYERE CC INC.-SAINT-VINCENT",
    "BDC": "BURLINGTON DIALYSIS CENTER",
    "BDD": "BELLEVILLE DIALYSIS CLINIC",
    "BGH": "THE BRANT COMMUNITY HEALTHCARE SYSTEM",
    "BHS": "BLUEWATER HEALTH - SARNIA",
    "BIC": "TORONTO REHAB BICKLE CENTRE",
    "BMH": "BRAMPTON CIVIC HOSPITAL",
    "BPH": "BRIDGEPOINT HEALTH",
    "BRK": "BLANCHE RIVER - KIRKLAND",
    "BRO": "BROCKVILLE DIALYSIS CLINIC",
    "BSH": "BRIGHTSHORES HEALTH SYSTEM",
    "CDC": "CORNWALL DIALYSIS CLINIC",
    "CGH": "CORNWALL GENERAL",
    "CHA": "CHATHAM - KENT HEALTH ALLIANCE",
    "CMH": "CAMBRIDGE MEMORIAL HOSPITAL",
    "CNC": "CHURCH NEPHROLOGY CENTRE",
    "CNI": "SUNNYBROOK SATELLITE",
    "COB": "NORTHUMBERLAND HILLS",
    "COL": "COLLINGWOOD GENERAL & MARINE",
    "CRC": "COMMUNITY RENAL CENTRE",
    "CTS": "CENTENARY SITE",
    "CVH": "TRILLIUM HEALTH PARTNERS - CREDIT VALLEY HOSPITAL",
    "ESH": "ERIE SHORES HEALTHCARE",
    "ETG": "ETOBICOKE GENERAL HOSPITAL",
    "GBH": "GREY-BRUCE HEALTH SERVICES - OWEN SOUND",
    "GFS": "FREEPORT SITE",
    "GGH": "GUELPH GENERAL HOSPITAL",
    "GRH": "GRAND RIVER HOSPITAL CORPORATION",
    "HDH": "HANOVER AND DISTRICT HOSPITAL",
    "HDM": "MUSKOKA ALGONQUIN HEALTHCARE",
    "HGH": "HAWKESBURY GENERAL HOSPITAL",
    "HHG": "HAMILTON GENERAL HOSPITAL",
    "HOM": "HOPITAL MONTFORT",
    "HPH": "HURON PERTH HOSPS PARTNERSHIP (STRATFORD)",
    "HRH": "HUMBER RIVER HEALTH",
    "HSN": "HEALTH SCIENCES NORTH",
    "HSU": "SCARBOROUGH HD SATELLITE UNIT",
    "HWH": "HEADWATERS HEALTH CARE",
    "JBH": "JOSEPH BRANT HOSPITAL",
    "JGE": "ST. JOSEPH'S GENERAL HOSPITAL (ELLIOTT LAKE)",
    "JHH": "ST. JOSEPH'S HEALTHCARE - HAMILTON",
    "JUH": "JURAVINSKI HOSPITAL",
    "KCC": "KIDNEY CARE CENTRE",
    "KGH": "KINGSTON GENERAL",
    "LHO": "LAKERIDGE HEALTH OSHAWA",
    "LHS": "LONDON HEALTH SCIENCES CENTRE",
    "LHW": "LAKERIDGE HEALTH WHITBY",
    "LIN": "ROSS MEMORIAL HOSPITAL (LINDSAY)",
    "LWD": "LAKE OF THE WOODS DISTRICT HOSPITAL",
    "MAH": "MACKENZIE HEALTH",
    "MCH": "MCMASTER CHILDREN'S HOSPITAL",
    "MFS": "MOOSE FACTORY SATELLITE - KINGSTON HEALTH SCIENCES CENTRE",
    "MGH": "MICHAEL GARRON HOSPITAL",
    "MHC": "MANITOULIN HEALTH CENTRE (LITTLE CURRENT)",
    "MNH": "MOUNT SINAI HOSPITAL",
    "MVH": "CORTELLUCCI VAUGHAN HOSPITAL",
    "NBH": "NORTH BAY REGIONAL HEALTH CENTRE",
    "NDC": "NAPANEE SATELLITE DIALYSIS UNIT",
    "NHS": "NIAGARA HEALTH SYSTEM",
    "NFS": "NIAGARA FALLS SITE",
    "NLT": "NEW LISKEARD - TEMISKAMING",
    "NWH": "NORTH WELLINGTON HEALTH CARE - PALMERSTON SITE",
    "NWS": "WELLAND SITE",
    "NYG": "NORTH YORK GENERAL",
    "OAK": "OAK RIDGES SATELLITE",
    "ODC": "OTTAWA DIALYSIS CLINIC",
    "OHI": "OTTAWA HEART INSTITUTE",
    "OSM": "ORILLIA SOLDIERS’ MEMORIAL HOSPITAL",
    "OTM": "HALTON HEALTHCARE SERVICES",
    "OVH": "OAK VALLEY HEALTH",
    "PET": "PETERBOROUGH REGIONAL HEALTH CENTRE",
    "PGG": "PEMBROKE GENERAL HOSPITAL",
    "PGH": "PENETANG GENERAL HOSPITAL",
    "PMC": "PEEL MEMORIAL CENTRE",
    "PRH": "PRINCESS MARGARET HOSPITAL",
    "PRO": "PROVIDENCE HEALTHCARE",
    "PSF": "PERTH AND SMITHS FALLS",
    "QCH": "QUEENSWAY CARLETON HOSPITAL",
    "QHB": "QUINTE HEALTHCARE (BANCROFT)",
    "QHP": "QUINTE HEALTHCARE (PICTON)",
    "RCC": "RENAL CARE CENTRE",
    "RVH": "ROYAL VICTORIA REGIONAL HEALTH CENTRE",
    "RVV": "RENFREW VICTORIA HOSPITAL",
    "SAH": "SAULT AREA HOSPITAL",
    "SBK": "SUNNYBROOK HEALTH SCIENCES CENTRE",
    "SGH": "SCARBOROUGH GENERAL SITE",
    "SHK": "SENSENBRENNER HOSPITAL (KAPUSKASING)",
    "SJH": "ST. JOSEPH’S HEALTH CENTRE TORONTO",
    "SJR": "ST.JOHN'S REHAB",
    "SMB": "ST. FRANCIS MEMORIAL HOSPITAL (BARRY'S BAY)",
    "SMG": "ST. MARY'S GENERAL HOSPITAL",
    "SMH": "ST. MICHAEL'S HOSPITAL",
    "SOS": "OHSWEKEN - SIX NATIONS",
    "SSC": "STONEY CREEK",
    "STH": "SOUTHLAKE HOSPITAL",
    "TBH": "THUNDER BAY REGIONAL HEALTH SCIENCES CENTRE",
    "TCS": "CIVIC SITE",
    "TDH": "TIMMINS AND DISTRICT HOSPITAL",
    "TEG": "TORONTO GENERAL - EATON GROUND",
    "TFF": "FORT FRANCES",
    "TGH": "TORONTO GENERAL HOSPITAL",
    "TMH": "TILLSONBURG DISTRICT MEMORIAL HOSPITAL",
    "TMS": "TRILLIUM MISSISSAUGA SITE",
    "TOH": "THE OTTAWA HOSPITAL",
    "TRI": "TORONTO REHAB INSTITUTE",
    "TRS": "RIVERSIDE SITE",
    "TSL": "SIOUX LOOKOUT",
    "TWH": "TORONTO WESTERN HOSPITAL",
    "TWT": "TRILLIUM WEST TORONTO SITE",
    "VAU": "VAUGHAN SATELLITE",
    "WGH": "WOODSTOCK GENERAL HOSPITAL",
    "WKC": "WESTMOUNT KIDNEY CARE CENTRE",
    "WLN": "ROYAL VICTORIA REGIONAL HEALTH CENTRE - WELLINGTON SATELLITE",
    "WMH": "WINCHESTER MEMORIAL HOSPITAL",
    "WPS": "WEST PARRY SOUND HEALTH CENTRE",
    "WRB": "WINDSOR REGIONAL BELL",
    "WRO": "WINDSOR REGIONAL OUELLETTE",
    "YHS": "YEE HONG SATELLITE - SCARBOROUGH FINCH - SATELLITE"
};

function normalizeLocationValue(value = '') {
    return (value || '').trim();
}

function formatLocationDisplay(value = '') {
    const trimmed = normalizeLocationValue(value);
    if (!trimmed) return 'Not specified';
    const parts = trimmed.split(':');
    if (parts.length > 1) {
        return parts.slice(1).join(':').trim();
    }
    return trimmed;
}

function escapeHtml(value = '') {
    return String(value || '').replace(/[&<>"']/g, char => {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
        return map[char] || char;
    });
}
const LOCATION_OPTION_ENTRIES = Object.entries(LOCATION_CODES).map(([code, name]) => {
    const value = code ? `${code}: ${name}` : (name || '');
    return {
        code,
        value,
        text: formatLocationDisplay(value)
    };
}).sort((a, b) => a.text.localeCompare(b.text, undefined, { sensitivity: 'base' }));
const LOCATION_VALUE_MAP = new Map();
const CANONICAL_TO_DISPLAY = new Map();
const displayCounts = {};
LOCATION_OPTION_ENTRIES.forEach(option => {
    const canonical = option.value;
    const normalized = normalizeLocationValue(canonical);
    if (!normalized) return;
    if (!LOCATION_VALUE_MAP.has(normalized)) {
        LOCATION_VALUE_MAP.set(normalized, canonical);
    }
    const baseDisplay = option.text;
    displayCounts[baseDisplay] = (displayCounts[baseDisplay] || 0) + 1;
});
LOCATION_OPTION_ENTRIES.forEach(option => {
    const canonical = option.value;
    const normalized = normalizeLocationValue(canonical);
    if (!normalized) return;
    const baseDisplay = option.text;
    const count = displayCounts[baseDisplay] || 1;
    const display = count === 1 ? baseDisplay : `${baseDisplay} (${option.code})`;
    CANONICAL_TO_DISPLAY.set(normalized, display);
});
const LOCATION_OPTION_LIST = LOCATION_OPTION_ENTRIES
    .map(option => {
        const canonical = option.value;
        const normalized = normalizeLocationValue(canonical);
        if (!normalized) return null;
        const display = CANONICAL_TO_DISPLAY.get(normalized) || option.text;
        return { canonical, normalized, display };
    })
    .filter(Boolean);
const LOCATION_SOURCE_LABELS = {
    randomization: 'Randomization unit',
    notification: 'Notification unit',
    base: 'Initial unit',
    unknown: ''
};
const UNIT_FILTER_SETTING_KEY = 'recruiting_unit_codes';
let availableUnitCodes = [];
let recruitingUnitCodes = [];
let recruitingUnitCodeSet = new Set();
let SQL;
let db = null;
let patientsData = [];
let dbChanged = false;
let encryptionState = null;
let currentUser = null;
let currentFilter = 'all';
let currentSearchTerm = '';
const currentSortKey = 'mrn';
const supportsDirectoryPicker = typeof window.showDirectoryPicker === 'function';
const supportsSaveFilePicker = typeof window.showSaveFilePicker === 'function';
let saveDirectoryHandle = null;
let saveDirectoryReady = false;
let autosaveTimer = null;
let autosaveInProgress = false;
let autosaveQueued = false;
let autosaveToggle = false;
let manualSaveInProgress = false;
let dbChangeCounter = 0;
let lastSavedChangeCounter = 0;
const AUTOSAVE_PREFIX_A = 'dialex-secure-latest-a-';
const AUTOSAVE_PREFIX_B = 'dialex-secure-latest-b-';
const AUTOSAVE_EXTENSION = '.enc';
const AUTOSAVE_LEGACY_FILE_A = 'dialex-secure-latest-a.enc';
const AUTOSAVE_LEGACY_FILE_B = 'dialex-secure-latest-b.enc';
const AUTOSAVE_DEBOUNCE_MS = 0;
const IMPORT_BACKUP_PREFIX = 'dialex-backup-';
const IMPORT_BACKUP_EXTENSION = '.enc';
const IMPORT_BACKUP_NAME_MAX = 40;
const SAVE_HANDLE_DB_NAME = 'dialex-save-handles';
const SAVE_HANDLE_STORE_NAME = 'handles';
const SAVE_HANDLE_KEY = 'save-directory';
const SAVE_HANDLE_PROBE_FILE = 'dialex-save-check.tmp';
let renderScheduled = false;

const $ = (id) => document.getElementById(id);
const THEME_STORAGE_KEY = 'dialex-theme';
const DEFAULT_THEME = 'dark';
const ALLOW_DATABASE_CREATION = false; // central setup only

function getSavedTheme() {
    try {
        return localStorage.getItem(THEME_STORAGE_KEY);
    } catch (error) {
        console.warn('Unable to read theme preference', error);
        return null;
    }
}

function applyTheme(theme) {
    const next = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    const toggle = $('theme-toggle');
    if (toggle) {
        toggle.textContent = next === 'dark' ? 'Dark theme' : 'Light theme';
        toggle.setAttribute('aria-pressed', next === 'dark' ? 'true' : 'false');
    }
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || DEFAULT_THEME;
    const next = current === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    try {
        localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch (error) {
        console.warn('Unable to store theme preference', error);
    }
}

function initTheme() {
    const saved = getSavedTheme();
    applyTheme(saved || DEFAULT_THEME);
}


async function setupSaveLocationControls() {
    const setFolderBtn = $('set-save-folder-btn');
    if (setFolderBtn) {
        if (supportsDirectoryPicker) {
            setFolderBtn.disabled = false;
            setFolderBtn.addEventListener('click', handleSetSaveFolder);
        } else {
            setFolderBtn.disabled = true;
            setFolderBtn.title = 'This browser does not support selecting a folder for continuous data saving.';
        }
    }
    const gateBtn = $('autosave-gate-btn');
    if (gateBtn) {
        gateBtn.addEventListener('click', handleSetSaveFolder);
    }
    try {
        await restoreSavedDirectoryHandle();
    } catch (error) {
        console.warn('Unable to restore save folder handle', error);
    }
    updateSaveFolderStatus();
    updateAppAccessState();
}

function updateSaveFolderStatus() {
    const statusEl = $('save-folder-status');
    const inlineEl = $('save-folder-inline');
    if (!statusEl && !inlineEl) return;
    let message = 'Required';
    if (!supportsDirectoryPicker) {
        message = 'Unavailable';
    } else if (saveDirectoryHandle && saveDirectoryReady) {
        message = saveDirectoryHandle.name || 'Selected folder';
    } else if (saveDirectoryHandle) {
        message = 'Permission needed';
    }
    if (statusEl) {
        statusEl.textContent = message;
    }
    if (inlineEl) {
        inlineEl.textContent = message;
    }
}

function updateAutosaveGate() {
    const gate = $('autosave-gate');
    if (!gate) return;
    const gateText = $('autosave-gate-text');
    const gateBtn = $('autosave-gate-btn');
    const message = getEditBlockingMessage();
    if (!message) {
        gate.classList.add('hidden');
        if (gateBtn) {
            gateBtn.classList.add('hidden');
            gateBtn.disabled = true;
        }
        return;
    }
    if (gateText) {
        gateText.textContent = message;
    }
    gate.classList.remove('hidden');
    if (gateBtn) {
        const showButton = supportsDirectoryPicker
            && Boolean(db)
            && Boolean(currentUser)
            && (!saveDirectoryHandle || !saveDirectoryReady);
        gateBtn.classList.toggle('hidden', !showButton);
        gateBtn.disabled = !showButton;
    }
}

function isSaveHandleStorageAvailable() {
    return typeof indexedDB !== 'undefined';
}

function openSaveHandleDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(SAVE_HANDLE_DB_NAME, 1);
        request.onupgradeneeded = () => {
            request.result.createObjectStore(SAVE_HANDLE_STORE_NAME);
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

function requestToPromise(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

function transactionToPromise(tx) {
    return new Promise((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error || new Error('Transaction failed'));
        tx.onabort = () => reject(tx.error || new Error('Transaction aborted'));
    });
}

async function storeSaveDirectoryHandle(handle) {
    if (!handle || !isSaveHandleStorageAvailable()) return false;
    try {
        const dbHandle = await openSaveHandleDatabase();
        const tx = dbHandle.transaction(SAVE_HANDLE_STORE_NAME, 'readwrite');
        tx.objectStore(SAVE_HANDLE_STORE_NAME).put(handle, SAVE_HANDLE_KEY);
        await transactionToPromise(tx);
        dbHandle.close();
        return true;
    } catch (error) {
        console.warn('Unable to store save folder handle', error);
        return false;
    }
}

async function loadSavedDirectoryHandle() {
    if (!isSaveHandleStorageAvailable()) return null;
    try {
        const dbHandle = await openSaveHandleDatabase();
        const tx = dbHandle.transaction(SAVE_HANDLE_STORE_NAME, 'readonly');
        const request = tx.objectStore(SAVE_HANDLE_STORE_NAME).get(SAVE_HANDLE_KEY);
        const handle = await requestToPromise(request);
        await transactionToPromise(tx);
        dbHandle.close();
        return handle || null;
    } catch (error) {
        console.warn('Unable to load save folder handle', error);
        return null;
    }
}

async function clearStoredSaveDirectoryHandle() {
    if (!isSaveHandleStorageAvailable()) return;
    try {
        const dbHandle = await openSaveHandleDatabase();
        const tx = dbHandle.transaction(SAVE_HANDLE_STORE_NAME, 'readwrite');
        tx.objectStore(SAVE_HANDLE_STORE_NAME).delete(SAVE_HANDLE_KEY);
        await transactionToPromise(tx);
        dbHandle.close();
    } catch (error) {
        console.warn('Unable to clear save folder handle', error);
    }
}

async function restoreSavedDirectoryHandle() {
    if (!supportsDirectoryPicker || !isSaveHandleStorageAvailable()) return;
    if (saveDirectoryHandle) return;
    const handle = await loadSavedDirectoryHandle();
    if (handle) {
        saveDirectoryHandle = handle;
    }
}

async function verifySaveDirectoryWritable(handle) {
    if (!handle) return false;
    const probeName = SAVE_HANDLE_PROBE_FILE;
    try {
        const probeHandle = await handle.getFileHandle(probeName, { create: true });
        const probeBlob = new Blob(['ok'], { type: 'text/plain' });
        await writeBlobToHandle(probeHandle, probeBlob);
        if (typeof handle.removeEntry === 'function') {
            await handle.removeEntry(probeName);
        }
        return true;
    } catch (error) {
        console.warn('Save folder write check failed', error);
        return false;
    }
}

async function validateSaveDirectoryForAutosave(options = {}) {
    const showMessages = options.showStatus;
    const requestPermission = options.requestPermission === true;
    saveDirectoryReady = false;
    if (!supportsDirectoryPicker) {
        updateSaveFolderStatus();
        updateAppAccessState();
        if (showMessages && db) {
            showStatus('Continuous data saving requires Google Chrome or Microsoft Edge.', 'error');
        }
        return false;
    }
    if (!saveDirectoryHandle) {
        updateSaveFolderStatus();
        updateAppAccessState();
        if (showMessages && db) {
            showStatus('Select a save folder to enable continuous data saving and editing.', 'error');
        }
        return false;
    }
    const allowed = await ensureDirectoryPermission(saveDirectoryHandle, { request: requestPermission });
    if (!allowed) {
        updateSaveFolderStatus();
        updateAppAccessState();
        if (showMessages && db) {
            showStatus('Save folder permission is required. Click "Set save folder".', 'error');
        }
        return false;
    }
    const writable = await verifySaveDirectoryWritable(saveDirectoryHandle);
    if (!writable) {
        await clearStoredSaveDirectoryHandle();
        saveDirectoryHandle = null;
        saveDirectoryReady = false;
        updateSaveFolderStatus();
        updateAppAccessState();
        if (showMessages && db) {
            showStatus('Save folder is not writable. Please select another folder.', 'error');
        }
        return false;
    }
    saveDirectoryReady = true;
    updateSaveFolderStatus();
    updateAppAccessState();
    if (dbChanged) {
        queueAutosave();
    }
    return true;
}


async function handleSetSaveFolder() {
    if (!supportsDirectoryPicker) {
        showStatus('Folder selection is not supported in this browser.', 'error');
        return;
    }
    try {
        const handle = await window.showDirectoryPicker({
            id: 'dialex-save-folder',
            mode: 'readwrite'
        });
        const allowed = await ensureDirectoryPermission(handle);
        if (!allowed) {
            showStatus('Permission to save in that folder was denied. Please select another folder.', 'error');
            return;
        }
        const writable = await verifySaveDirectoryWritable(handle);
        if (!writable) {
            showStatus('The selected folder is not writable. Please select another folder.', 'error');
            return;
        }
        saveDirectoryHandle = handle;
        saveDirectoryReady = true;
        const stored = await storeSaveDirectoryHandle(handle);
        updateSaveFolderStatus();
        updateAppAccessState();
        if (dbChanged) {
            queueAutosave();
        }
        if (stored) {
            showStatus(`Save folder set to "${handle.name}". Autosave is enabled.`, 'success');
        } else {
            showStatus(`Save folder set to "${handle.name}". Autosave is enabled for this session.`, 'status');
        }
    } catch (error) {
        if (error && error.name === 'AbortError') {
            showStatus('Folder selection canceled.', 'status');
        } else {
            console.error('Unable to set save folder', error);
            showStatus('Unable to set save folder: ' + (error && error.message ? error.message : error), 'error');
        }
    }
}

async function ensureDirectoryPermission(handle, options = {}) {
    if (!handle) return false;
    const permissionOptions = { mode: 'readwrite' };
    const allowRequest = options.request !== false;
    if (typeof handle.queryPermission === 'function') {
        const permission = await handle.queryPermission(permissionOptions);
        if (permission === 'granted') {
            return true;
        }
        if (permission === 'denied') {
            return false;
        }
        if (permission === 'prompt' && !allowRequest) {
            return false;
        }
    }
    if (allowRequest && typeof handle.requestPermission === 'function') {
        const result = await handle.requestPermission(permissionOptions);
        return result === 'granted';
    }
    return true;
}

function handleBeforeUnload(event) {
    if (!db || !dbChanged) return;
    event.preventDefault();
    event.returnValue = 'You have unsaved DIALEX changes. Save before leaving?';
}

function isAutosaveEncryptionReady() {
    return Boolean(
        encryptionState
        && encryptionState.mode === 'multi'
        && encryptionState.dataKey
        && Array.isArray(encryptionState.wraps)
        && encryptionState.wraps.length
    );
}
