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

async function findDataKeyForPassword(password, wraps = []) {
    for (const wrapEntry of wraps) {
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

async function decryptDatabaseV2(bytes, password) {
    const payload = parseEncryptedPayloadV2(bytes);
    if (!payload || !Array.isArray(payload.wraps)) {
        throw new Error("Invalid encrypted file format.");
    }
    const { dataKey, unlockId } = await findDataKeyForPassword(password, payload.wraps);
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

async function decryptDatabasePayload(packedData, password) {
    if (isV2EncryptedPayload(packedData)) {
        return await decryptDatabaseV2(packedData, password);
    }
    const dataBytes = await decryptData(packedData, password);
    return {
        dataBytes,
        encryptionState: { mode: 'legacy', unlockId: 'legacy' }
    };
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
        autocomplete: 'new-password'
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
    incl_age: ['birth_date'],
    incl_dialysis_90d: ['dialysis_start_date'],
    incl_incentre_hd: ['dialysis_unit'],
    incl_health_card: ['health_card', 'health_card_province']
};
const INCLUSION_FIELD_LIST = Object.values(INCLUSION_FIELD_MAP)
    .reduce((acc, fields) => acc.concat(fields), []);
const INCLUSION_FIELD_MESSAGES = {
    incl_age: 'Update Date of Birth to recalculate the age criterion.',
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
}

function updateSaveFolderStatus() {
    const statusEl = $('save-folder-status');
    if (!statusEl) return;
    let message = 'Required';
    if (!supportsDirectoryPicker) {
        message = 'Unavailable';
    } else if (saveDirectoryHandle && saveDirectoryReady) {
        message = saveDirectoryHandle.name || 'Selected folder';
    } else if (saveDirectoryHandle) {
        message = 'Permission needed';
    }
    statusEl.textContent = message;
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

function formatTimestampForFilename(date = new Date()) {
    return date.toISOString().replace(/[:T]/g, '-').split('.')[0];
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

        const onSubmit = (event) => {
            event.preventDefault();
            errorEl.classList.add('hidden');
            const password = passwordInput.value;
            if (!password.length) {
                showError('Password is required.');
                passwordInput.focus();
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
    const unlocked = hasDb && hasUser;
    const canEdit = Boolean(unlocked && saveDirectoryReady && isAutosaveEncryptionReady());
    const assessmentControls = $('assessment-controls');
    const tableContainer = $('table-container');
    if (assessmentControls) assessmentControls.classList.toggle('hidden', !canEdit);
    if (tableContainer) tableContainer.classList.toggle('hidden', !canEdit);

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
    const valid = await verifyPassword(password, user.password_salt, user.password_hash);
    if (!valid) {
        return { ok: false, message: 'Invalid username or password.' };
    }
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
        INSERT INTO users (username, display_name, password_salt, password_hash, role, active)
        VALUES (?, ?, ?, ?, ?, 1)
    `);
    stmt.run([
        normalized,
        displayName,
        record.salt,
        record.hash,
        role || 'user'
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

async function updateUserPassword(username, newPassword) {
    const normalized = normalizeUsername(username);
    const record = await createPasswordRecord(newPassword);
    const stmt = db.prepare(`
        UPDATE users
        SET password_salt = ?, password_hash = ?, updated_at = datetime('now')
        WHERE username = ?
    `);
    stmt.run([record.salt, record.hash, normalized]);
    stmt.free();
    await upsertUserWrap(normalized, newPassword);
    logAuditEvent('user_password_reset', { username: normalized }, {
        targetType: 'user',
        targetId: normalized
    });
}

function loadUsers() {
    if (!db) return [];
    const stmt = db.prepare('SELECT username, display_name, role, active FROM users ORDER BY username');
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
        const statusLabel = Number(user.active) ? 'Active' : 'Disabled';
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
            SET active = ?, updated_at = datetime('now')
            WHERE username = ?
        `);
        stmt.run([nextActive, target.username]);
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
            autocomplete: 'new-password'
        });
        if (!newPassword) return;
        if (newPassword.length < MIN_PASSWORD_LENGTH) {
            showStatus(`Passwords must be at least ${MIN_PASSWORD_LENGTH} characters.`, 'error');
            return;
        }
        await updateUserPassword(target.username, newPassword);
        markDatabaseChanged();
        showStatus('Password updated.', 'success');
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
        const passwordInput = $('login-password');
        const errorEl = $('login-error');
        const cancelBtn = $('login-cancel-btn');
        const unloadBtn = $('login-unload-btn');
        const submitBtn = $('login-submit-btn');
        const closeBtn = $('login-modal-close');
        const previouslyFocused = document.activeElement;
        const allowCancel = Boolean(options.allowCancel);
        let resolved = false;

        const cleanup = (result) => {
            if (resolved) return;
            resolved = true;
            modal.classList.remove('active');
            form.removeEventListener('submit', onSubmit);
            if (cancelBtn) cancelBtn.removeEventListener('click', onCancel);
            if (unloadBtn) unloadBtn.removeEventListener('click', onUnload);
            if (closeBtn) {
                closeBtn.removeEventListener('click', onCancel);
                closeBtn.removeEventListener('keydown', onCloseKeydown);
            }
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
            errorEl.textContent = '';
            errorEl.classList.add('hidden');
            const username = usernameInput.value;
            const password = passwordInput.value;
            submitBtn.disabled = true;
            const result = await authenticateUser(username, password);
            submitBtn.disabled = false;
            if (!result.ok) {
                showError(result.message || 'Unable to sign in.');
                passwordInput.focus();
                passwordInput.select();
                return;
            }
            cleanup({ action: 'login', user: result.user });
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
        usernameInput.value = '';
        passwordInput.value = '';
        errorEl.textContent = '';
        errorEl.classList.add('hidden');

        if (cancelBtn) cancelBtn.classList.toggle('hidden', !allowCancel);
        if (closeBtn) closeBtn.classList.toggle('hidden', !allowCancel);
        modal.classList.add('active');

        form.addEventListener('submit', onSubmit);
        if (cancelBtn) cancelBtn.addEventListener('click', onCancel);
        if (unloadBtn) unloadBtn.addEventListener('click', onUnload);
        if (closeBtn) {
            closeBtn.addEventListener('click', onCancel);
            closeBtn.addEventListener('keydown', onCloseKeydown);
        }
        modal.addEventListener('click', onBackdropClick);
        document.addEventListener('keydown', onKeyDown);
        requestAnimationFrame(() => usernameInput.focus());
    });
}

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
    const hasHealthCard = Boolean((patient.health_card || '').trim());
    const hcnProvince = (patient.health_card_province || '').trim();
    const requiresDialysisUnit = patient.incl_incentre_hd === 1;
    const locationValue = requiresDialysisUnit ? getDialysisUnitCanonical(patient) : '';
    const hasDialysisUnit = requiresDialysisUnit && Boolean(normalizeLocationValue(locationValue));
    const hasDialysisHistory = Boolean(patient.dialysis_start_date) || Boolean(patient.dialysis_duration_confirmed);
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
    const birthDateValue = patient.birth_date || '';
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
                    <input type="date" class="table-input" value="${birthDateValue}" ${isLocked ? 'disabled' : ''} onchange="updatePatientBirthDate(${patient._index}, this.value)">
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
                ${statusBadge}
                <div class="expand-indicator right ${expandedClass}" onclick="togglePatientRow(${patient._index})">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="9 18 15 12 9 6"></polyline>
                    </svg>
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
    const notificationDisplay = patient.notification_date || '';
    const notificationFriendly = formatFriendlyDate(patient.notification_date);
    const optOutStatus = patient.opt_out_status || OPT_OUT_STATUS.PENDING;
    const optOutDateDisplay = patient.opt_out_date || '';
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
    const dialysisStartDisplay = patient.dialysis_start_date || '';
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
                            <input type="date" class="table-input inline-date" value="${dialysisStartDisplay}" ${isLocked ? 'disabled' : ''} onchange="updateDialysisStartDate(${patient._index}, this.value)">
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
                        <input type="date" class="table-input inline-date" value="${notificationDisplay}" placeholder="Select date" ${isLocked ? 'disabled' : ''} onchange="updateInlineNotification(${patient._index}, this.value)">
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
                            <input type="date" class="table-input inline-date" value="${optOutDateDisplay}" placeholder="Select date" ${optOutDateDisabled} onchange="updateOptOutDate(${patient._index}, this.value)">
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
            showRecordWarning('Enter notification date as YYYY-MM-DD (or MM/DD/YYYY).', 'error');
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
        showRecordWarning('Enter opt-out date as YYYY-MM-DD (or MM/DD/YYYY).', 'error');
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
        showRecordWarning('Enter birth date as YYYY-MM-DD (or MM/DD/YYYY).', 'error');
        renderPatientTable();
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
    showRecordWarning('');
}

function updatePatientAge(index, value) {
    const patient = patientsData[index];
    if (!patient) return;
    refreshPatientRow(patient);
    showRecordWarning('Age is calculated from Date of Birth. Update DOB to change age.', 'error');
    highlightInclusionSource(patient._index, 'incl_age');
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
    if (firstEligible.getTime() > Date.now()) {
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
        patient.dialysis_start_date = '';
        patient.dialysis_duration_confirmed = 0;
    } else {
        const normalized = normalizeISODateString(raw);
        if (!normalized) {
            showRecordWarning('Enter dialysis start date as YYYY-MM-DD (or MM/DD/YYYY).', 'error');
            renderPatientTable();
            return;
        }
        if (patient.birth_date) {
            const birth = parseISODate(patient.birth_date);
            const start = parseISODate(normalized);
            if (birth && start && start.getTime() <= birth.getTime()) {
                showRecordWarning('Dialysis start date must be after birth date.', 'error');
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
    if (firstEligible.getTime() > Date.now()) {
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
        const stmt = db.prepare('INSERT OR IGNORE INTO study_ids (study_id) VALUES (?)');
        stmt.run([normalized]);
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
        patient.locked_at = new Date().toISOString();
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
    const value = field === 'mrn' ? getDisplayMrnValue(patient.mrn) : patient[field];
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
    return new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
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
                datetime('now'), ?, ?, ?, ?, ?, ?
            )
        `);
        stmt.run([actorUsername, actorRole, action, targetType, targetId, detailText]);
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
            patient.created_at = createdAtValue || getSqlTimestamp();
        }
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
                COALESCE(?, datetime('now')), datetime('now')
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
            createdAtValue
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
        candidate = `${TEMP_MRN_PREFIX}${Date.now()}-${attempts++}`;
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
            datetime('now'), datetime('now')
        )
    `);
    const importUsername = getCurrentUsername();
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
        ].concat(inclusionValues, exclusionValues);
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

function getField(row, candidates) {
    if (!row) return '';
    const normalizedCandidates = candidates.map(normalizeKey);
    for (const key of Object.keys(row)) {
        const normalizedKey = normalizeKey(key);
        if (normalizedCandidates.includes(normalizedKey)) {
            const value = row[key];
            if (value === undefined || value === null) continue;
            const trimmed = String(value).trim();
            if (trimmed) return trimmed;
        }
    }
    return '';
}

function getPatientKey(patient) {
    if (!patient) return '';
    return patient.mrn || `__idx-${patient._index}`;
}

function parseNumber(value) {
    if (value === null || value === undefined || value === '') return null;
    const num = Number(value);
    return Number.isNaN(num) ? null : num;
}

function parseBoolean(value) {
    if (value === null || value === undefined) return false;
    const normalized = String(value).trim().toLowerCase();
    if (!normalized) return false;
    return ['yes', 'true', '1', 'y'].includes(normalized);
}

function parseLegacyDate(value) {
    if (!value) return null;
    const trimmed = String(value).trim();
    if (!trimmed) return null;
    if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
        return parseISODate(trimmed);
    }
    const parts = trimmed.split(/[\/\-]/).map(Number);
    if (parts.length !== 3) return null;
    let day, month, year;
    if (parts[2] > 1900) {
        [day, month, year] = parts;
    } else {
        [year, month, day] = parts;
    }
    if (!day || !month || !year) return null;
    const date = new Date(year, month - 1, day);
    return Number.isNaN(date.getTime()) ? null : date;
}

function normalizeLegacyDate(value) {
    const date = parseLegacyDate(value);
    return date ? formatISODate(date) : '';
}

function calculateAgeFromDate(date) {
    if (!date) return null;
    const today = new Date();
    let age = today.getFullYear() - date.getFullYear();
    const m = today.getMonth() - date.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < date.getDate())) {
        age--;
    }
    return age;
}

function normalizeHealthCardValue(value = '') {
    return (value || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}

function inferProvinceFromHealthCard(value) {
    // Disabled: do not infer; require explicit entry/import
    return '';
}

function normalizeKey(key) {
    return (key || '').toString().toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function parseLegacyRegistrationCSV(csvText) {
    if (!csvText || !csvText.trim()) {
        throw new Error('The CSV file is empty.');
    }
    const rawLines = csvText.split(/\r\n|\n/);
    while (rawLines.length > 0) {
        const cleaned = rawLines[0].replace(/"/g, '').trim();
        if (cleaned === '' || /^,+$/.test(cleaned)) {
            rawLines.shift();
        } else {
            break;
        }
    }
    const records = reconstructCSVFromLines(rawLines).filter(line => line.trim() !== '');
    if (records.length <= HEADERS_LINE_INDEX) {
        throw new Error('Unable to locate header row in CSV.');
    }
    const rawHeaders = parseCSVLine(records[HEADERS_LINE_INDEX]);
    const headers = rawHeaders.map(h => h.replace(/\r?\n|\r/g, ' ').replace(/\s+/g, ' ').trim());
    if (!headers.length) {
        throw new Error('CSV did not contain recognizable headers.');
    }
    const data = [];
    for (let i = FIRST_DATA_LINE_INDEX; i < records.length; i++) {
        const record = records[i];
        if (!record || !record.trim()) continue;
        const values = parseCSVLine(record);
        if (values.length < headers.length) {
            continue;
        }
        const row = {};
        headers.forEach((header, idx) => {
            row[header] = values[idx] || '';
        });
        if ((row[LOCATION_HEADER] || '').trim() !== '') {
            data.push(row);
        }
    }
    if (!data.length) {
        throw new Error('CSV did not contain any usable patient rows.');
    }
    return data;
}

function reconstructCSVFromLines(lines) {
    const records = [];
    let currentLine = '';
    lines.forEach(line => {
        if (currentLine.length > 0) {
            currentLine += '\n' + line;
        } else {
            currentLine = line;
        }
        const quoteCount = (currentLine.match(/"/g) || []).length;
        if (quoteCount % 2 === 0) {
            records.push(currentLine);
            currentLine = '';
        }
    });
    if (currentLine.trim().length > 0) {
        records.push(currentLine);
    }
    return records;
}

function parseCSVLine(line) {
    const values = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') {
            if (inQuotes && line[i + 1] === '"') {
                current += '"';
                i++;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (char === ',' && !inQuotes) {
            values.push(current.replace(/^"|"$/g, '').trim());
            current = '';
        } else {
            current += char;
        }
    }
    values.push(current.replace(/^"|"$/g, '').trim());
    return values;
}

function analyzePreScreeningRows(rows) {
    const summary = {
        total: rows.length,
        eligible: 0,
        ineligible: 0,
        breakdown: {
            ageUnder45: 0,
            age45to59NoDiabetes: 0,
            daysUnderThreshold: 0,
            invalidModality: 0,
            missingHealthCard: 0,
            invalidDates: 0
        },
        details: []
    };
    rows.forEach(row => {
        const mrn = (row[MRN_HEADER] || '').toString().trim();
        const locationCode = getField(row, [LOCATION_HEADER]) || '';
        const patientName = getPatientNameFromRow(row);
        const healthCard = getField(row, [LAST_HCN_HEADER, 'Latest Known HCN', HCN_HEADER]) || '';
        const birthDate = parseLegacyDate(getField(row, [BIRTH_DATE_HEADER]));
        const dialysisStart = parseLegacyDate(getField(row, [START_DATE_HEADER]));
        let modalityCode = getField(row, [MODALITY_HEADER, 'Current Modality', 'Latest Modality']) || '';
        if (!VALID_MODALITY_CODES.includes(modalityCode) && DISPLAY_TO_PREFERRED_CODE[modalityCode]) {
            modalityCode = DISPLAY_TO_PREFERRED_CODE[modalityCode];
        }
        const hasValidModality = VALID_MODALITY_CODES.includes(modalityCode);
        const hasDiabetes = parseBoolean(getField(row, [DIAB_TYPE1_HEADER])) ||
                            parseBoolean(getField(row, [DIAB_TYPE2_HEADER]));
        const age = calculateAgeFromDate(birthDate);
        const daysOnDialysis = calculateDaysOnDialysis(dialysisStart);
        const reasons = [];

        if (!healthCard) {
            summary.breakdown.missingHealthCard++;
            reasons.push('Missing health card number');
        } else if (!birthDate || !dialysisStart) {
            summary.breakdown.invalidDates++;
            reasons.push('Invalid or missing birth/start date');
        } else {
            if (typeof age === 'number') {
                if (age < 45) {
                    summary.breakdown.ageUnder45++;
                    reasons.push(`Age ${age} < 45`);
                } else if (age < 60 && !hasDiabetes) {
                    summary.breakdown.age45to59NoDiabetes++;
                    reasons.push(`Age ${age} without diabetes`);
                }
            }
            if (typeof daysOnDialysis === 'number' && daysOnDialysis < MIN_DIALYSIS_DAYS) {
                summary.breakdown.daysUnderThreshold++;
                reasons.push(`Only ${daysOnDialysis} days on dialysis (needs ${MIN_DIALYSIS_DAYS}+)`);
            }
            if (!hasValidModality) {
                summary.breakdown.invalidModality++;
                reasons.push('Invalid hemodialysis modality');
            }
        }

        if (reasons.length === 0) {
            summary.eligible++;
        } else {
            summary.details.push({
                name: patientName,
                mrn,
                location: locationCode,
                reason: reasons.join('; ')
            });
        }
    });
    summary.ineligible = summary.total - summary.eligible;
    return summary;
}

function calculateDaysOnDialysis(startDate) {
    if (!startDate) return null;
    const diff = Date.now() - startDate.getTime();
    if (Number.isNaN(diff)) return null;
    return Math.floor(diff / MS_PER_DAY);
}

function updatePrescreenUI(summary) {
    const container = $('prescreen-results');
    if (!container || !summary) return;
    if (summary.total === 0) {
        container.classList.add('hidden');
        return;
    }
    container.classList.remove('hidden');
    $('ps-total').textContent = summary.total;
    $('ps-eligible').textContent = summary.eligible;
    $('ps-ineligible').textContent = summary.ineligible;
    $('ps-age-under45').textContent = summary.breakdown.ageUnder45;
    $('ps-age45-59-nodm').textContent = summary.breakdown.age45to59NoDiabetes;
    $('ps-days-under').textContent = summary.breakdown.daysUnderThreshold;
    $('ps-invalid-modality').textContent = summary.breakdown.invalidModality;
    $('ps-missing-hcn').textContent = summary.breakdown.missingHealthCard;
    $('ps-invalid-dates').textContent = summary.breakdown.invalidDates;

    const tabs = $('ps-tabs');
    const tabPanels = $('ps-tabpanels');
    const ineligiblePanel = $('ps-panel-ineligible');
    if (tabs) {
        tabs.style.display = 'none';
        tabs.innerHTML = '';
    }
    if (tabPanels) {
        tabPanels.style.display = 'none';
    }
    if (ineligiblePanel) {
        ineligiblePanel.innerHTML = '';
        ineligiblePanel.style.display = 'none';
        ineligiblePanel.classList.remove('active');
    }
}

function getPatientNameFromRow(row) {
    if (!row) return 'Unnamed Patient';
    const direct = getField(row, [
        'Patient Name',
        'Name',
        'Patient Name (Last, First)',
        'Full Name',
        'Patient Full Name'
    ]);
    if (direct) return direct;
    const first = getField(row, ['Patient First Name', 'Patient  First Name', 'First Name', 'Given Name', 'Patient Given Name']);
    const last = getField(row, ['Patient Last Name', 'Last Name', 'Family Name', 'Surname', 'Patient Surname']);
    const parts = [];
    if (first) parts.push(first);
    if (last) parts.push(last);
    if (parts.length > 0) {
        return parts.join(' ');
    }
    const mrn = getField(row, [MRN_HEADER]);
    return mrn ? `Patient (MRN: ${mrn})` : 'Unnamed Patient';
}

function computeInclusionAge(age, hasDiabetes) {
    if (age === null || age === undefined) return 0;
    if (age >= 60) return 1;
    if (age >= 45 && age <= 59 && hasDiabetes) return 1;
    return 0;
}

function normalizeOptOutStatus(rawStatus, legacyDidNotOptOut = 0) {
    const value = (rawStatus || '').toLowerCase();
    if (Object.values(OPT_OUT_STATUS).includes(value)) return value;
    if (legacyDidNotOptOut) return OPT_OUT_STATUS.DID_NOT;
    return OPT_OUT_STATUS.PENDING;
}

function recalcDialysisInclusion(patient) {
    if (!patient) return;
    patient.incl_dialysis_90d = patient.dialysis_duration_confirmed
        ? 1
        : meetsDialysisDays(patient.dialysis_start_date);
}

function meetsDialysisDays(dialysisStartIso) {
    const start = parseISODate(dialysisStartIso);
    if (!start) return 0;
    const diff = (Date.now() - start.getTime()) / MS_PER_DAY;
    return diff >= MIN_DIALYSIS_DAYS ? 1 : 0;
}

function computeFirstEligibleDate(patient) {
    const dialysisStart = parseISODate(patient.dialysis_start_date);
    const notification = parseISODate(patient.notification_date);
    if (!notification) return null;
    let ninety = dialysisStart ? addDays(dialysisStart, MIN_DIALYSIS_DAYS) : null;
    if (!ninety && patient.dialysis_duration_confirmed) {
        ninety = new Date(notification.getTime());
    }
    if (!ninety) return null;
    const optOut = addDays(notification, NOTIFICATION_BUFFER_DAYS);
        return new Date(Math.max(ninety.getTime(), optOut.getTime()));
    }

function canRandomizePatient(patient) {
    return getRandomizationIssues(patient).length === 0;
}

function getRandomizationIssues(patient) {
    const issues = [];
    if (!patient) return ['Missing patient record'];
    if (!patient.inclusionMet) {
        issues.push('Complete inclusion checklist');
    }
    if (!patient.noExclusions) {
        issues.push('Resolve exclusions');
    }
    if (!patient.no_exclusions_confirmed) {
        issues.push('Confirm "No exclusions"');
    }
    if (patient.opt_out_status === OPT_OUT_STATUS.PENDING) {
        issues.push('Set opt-out status');
    }
    if (patient.opt_out_status === OPT_OUT_STATUS.OPTED_OUT) {
        issues.push('Patient opted out');
    }
    if (!patient.incl_health_card) {
        issues.push('Enter valid health insurance card number');
    }
    if (!patient.notification_date) {
        issues.push('Set notification date');
    }
    if (!patient.dialysis_start_date && !patient.dialysis_duration_confirmed) {
        issues.push('Enter dialysis start date or confirm ≥90 days');
    }
    const firstEligible = computeFirstEligibleDate(patient);
    if (firstEligible && firstEligible.getTime() > Date.now()) {
        issues.push(`Eligible on ${formatISODate(firstEligible)}`);
    }
    return issues;
}

function parseISODate(value) {
    if (!value) return null;
    const parts = value.split('-').map(Number);
    if (parts.length !== 3) return null;
    const [y, m, d] = parts;
    const date = new Date(y, m - 1, d);
    return Number.isNaN(date.getTime()) ? null : date;
}

function addDays(date, days) {
    const copy = new Date(date.getTime());
    copy.setDate(copy.getDate() + days);
    return copy;
}

function formatISODate(date) {
    if (!date) return '';
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
}

const FRIENDLY_FORMAT = new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    year: 'numeric'
});

function formatFriendlyDate(value) {
    if (!value) return '';
    const date = parseISODate(value);
    if (!date) return '';
    return FRIENDLY_FORMAT.format(date);
}

function formatDisplayDateTime(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function normalizeISODateString(value) {
    const trimmed = (value || '').trim();
    if (!trimmed) return '';
    if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return trimmed;
    const parsed = parseLegacyDate(trimmed);
    return parsed ? formatISODate(parsed) : '';
}

function normalizeStudyIdValue(value = '') {
    const trimmed = (value || '').trim();
    if (!trimmed) return '';
    const upper = trimmed.toUpperCase();
    return STUDY_ID_REGEX.test(upper) ? upper : '';
}

function formatStudyIdInput(value = '') {
    const cleaned = (value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const segments = ['', '', ''];
    const patterns = [
        { len: 4, regex: /\d/ },
        { len: 3, regex: /[A-Z]/ },
        { len: 3, regex: /\d/ }
    ];
    let segIndex = 0;
    for (const char of cleaned) {
        while (segIndex < patterns.length && segments[segIndex].length >= patterns[segIndex].len) {
            segIndex++;
        }
        if (segIndex >= patterns.length) break;
        if (patterns[segIndex].regex.test(char)) {
            segments[segIndex] += char;
        }
    }
    let formatted = '';
    if (segments[0]) {
        formatted += segments[0];
    }
    if (segments[0] && (segments[0].length === patterns[0].len || segments[1])) {
        formatted += '-';
    }
    if (segments[1]) {
        formatted += segments[1];
    }
    if (segments[1] && (segments[1].length === patterns[1].len || segments[2])) {
        formatted += '-';
    }
    if (segments[2]) {
        formatted += segments[2];
    }
    return formatted.replace(/-+$/, '');
}

function handleStudyIdInput(index, input) {
    if (!input) return;
    const formatted = formatStudyIdInput(input.value);
    input.value = formatted;
}

function startOfToday() {
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), now.getDate());
}

function isDateInFuture(date) {
    if (!date) return false;
    return date.getTime() > startOfToday().getTime();
}

function isFutureISODateString(value) {
    const date = parseISODate(value);
    return isDateInFuture(date);
}

function buildLocationOptionsHtml(selectedValue = '') {
    const normalizedSelected = normalizeLocationValue(selectedValue);
    const options = ['<option value="">None (not in-centre)</option>'];
    LOCATION_OPTION_LIST.forEach(option => {
        const selected = option.normalized === normalizedSelected ? ' selected' : '';
        options.push(`<option value="${escapeHtml(option.canonical)}"${selected}>${escapeHtml(option.display)}</option>`);
    });
    return options.join('');
}

function getDialysisUnitCanonical(patient = {}) {
    if (patient.incl_incentre_hd !== 1) {
        return '';
    }
    const source = patient.location_at_randomization || patient.location || '';
    return getCanonicalLocationValue(source);
}

function getLocationDisplayFromCanonical(canonical = '') {
    const normalized = normalizeLocationValue(canonical);
    if (!normalized) return '';
    return CANONICAL_TO_DISPLAY.get(normalized) || formatLocationDisplay(normalized);
}

function getLocationNameFromCode(code = '') {
    const upper = (code || '').trim().toUpperCase();
    if (!upper) return '';
    return LOCATION_CODES[upper] || '';
}

function getMostRecentLocationInfo(patient = {}) {
    const randomization = normalizeLocationValue(getCanonicalLocationValue(patient.location_at_randomization));
    if (randomization) {
        return { value: randomization, source: 'randomization' };
    }
    const base = normalizeLocationValue(getCanonicalLocationValue(patient.location));
    if (base) {
        return { value: base, source: 'base' };
    }
    return { value: '', source: 'unknown' };
}

function getCanonicalLocationValue(value = '') {
    const normalized = normalizeLocationValue(value);
    if (!normalized) return '';
    return LOCATION_VALUE_MAP.get(normalized) || normalized;
}

function getLocationCodeFromValue(value = '') {
    const normalized = normalizeLocationValue(value);
    if (!normalized) return '';
    if (normalized.includes(':')) {
        return normalized.split(':')[0].trim().toUpperCase();
    }
    const token = normalized.split(/\s+/)[0];
    return (token || '').toUpperCase();
}

function normalizeUnitCode(value = '') {
    return (value || '').trim().toUpperCase();
}

function loadAvailableUnitCodes() {
    availableUnitCodes = [];
    if (!db) return;
    const codes = new Set();
    let stmt;
    try {
        stmt = db.prepare('SELECT study_id FROM study_ids');
        while (stmt.step()) {
            const row = stmt.getAsObject();
            const code = normalizeUnitCode(extractStudySite(row.study_id || ''));
            if (code) codes.add(code);
        }
    } catch (error) {
        console.warn('Unable to read study IDs for units', error);
    } finally {
        if (stmt) stmt.free();
    }
    availableUnitCodes = Array.from(codes).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
}

function readSiteSetting(key) {
    if (!db) return '';
    let stmt;
    try {
        stmt = db.prepare('SELECT value FROM site_settings WHERE key = ?');
        stmt.bind([key]);
        if (stmt.step()) {
            const row = stmt.getAsObject();
            return row.value || '';
        }
    } catch (error) {
        console.warn('Unable to read site setting', error);
    } finally {
        if (stmt) stmt.free();
    }
    return '';
}

function writeSiteSetting(key, value) {
    if (!db) return;
    try {
        const stmt = db.prepare(`
            INSERT OR REPLACE INTO site_settings (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
        `);
        stmt.run([key, value]);
        stmt.free();
        markDatabaseChanged();
    } catch (error) {
        console.warn('Unable to save site setting', error);
    }
}

function setRecruitingUnitCodes(codes = [], persist = false) {
    const normalized = Array.from(new Set((codes || []).map(normalizeUnitCode).filter(Boolean)));
    recruitingUnitCodes = normalized;
    recruitingUnitCodeSet = new Set(normalized);
    updateRecruitingUnitSummary();
    if (persist) {
        writeSiteSetting(UNIT_FILTER_SETTING_KEY, JSON.stringify(normalized));
    }
}

function loadRecruitingUnitSelection() {
    if (!db) {
        setRecruitingUnitCodes([]);
        return;
    }
    let codes = [];
    const raw = readSiteSetting(UNIT_FILTER_SETTING_KEY);
    if (raw) {
        try {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) {
                codes = parsed;
            }
        } catch (error) {
            console.warn('Unable to parse recruiting unit settings', error);
        }
    }
    codes = codes.map(normalizeUnitCode).filter(Boolean);
    if (!availableUnitCodes.length) {
        codes = [];
    } else {
        const allowed = new Set(availableUnitCodes);
        codes = codes.filter(code => allowed.has(code));
        if (codes.length === availableUnitCodes.length) {
            codes = [];
        }
    }
    setRecruitingUnitCodes(codes);
}

function updateRecruitingUnitSummary() {
    const summary = $('unit-filter-summary');
    if (!summary) return;
    if (!db) {
        summary.textContent = 'No database loaded';
        return;
    }
    if (!availableUnitCodes.length) {
        summary.textContent = 'No units loaded';
        return;
    }
    if (!recruitingUnitCodes.length) {
        summary.textContent = 'All units';
        return;
    }
    summary.textContent = `${recruitingUnitCodes.length} selected`;
}

function renderRecruitingUnitOptions() {
    const list = $('unit-filter-list');
    const empty = $('unit-filter-empty');
    if (!list) return;
    list.innerHTML = '';
    if (!availableUnitCodes.length) {
        if (empty) empty.classList.remove('hidden');
        return;
    }
    if (empty) empty.classList.add('hidden');
    const selection = recruitingUnitCodes.length
        ? new Set(recruitingUnitCodes)
        : new Set(availableUnitCodes);
    const fragment = document.createDocumentFragment();
    availableUnitCodes.forEach(code => {
        const name = getLocationNameFromCode(code);
        const label = name ? `${code} - ${name}` : code;
        const option = document.createElement('label');
        option.className = 'unit-filter-option';
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.dataset.unitCode = code;
        checkbox.checked = selection.has(code);
        const text = document.createElement('span');
        text.textContent = label;
        option.appendChild(checkbox);
        option.appendChild(text);
        fragment.appendChild(option);
    });
    list.appendChild(fragment);
}

function openRecruitingUnitModal() {
    if (!db) return;
    renderRecruitingUnitOptions();
    const modal = $('unit-filter-modal');
    if (modal) modal.classList.add('active');
}

function closeRecruitingUnitModal() {
    const modal = $('unit-filter-modal');
    if (modal) modal.classList.remove('active');
}

function saveRecruitingUnitSelection() {
    const list = $('unit-filter-list');
    if (!list) return;
    const selected = Array.from(list.querySelectorAll('input[type="checkbox"][data-unit-code]'))
        .filter(input => input.checked)
        .map(input => input.dataset.unitCode);
    let next = Array.from(new Set(selected.map(normalizeUnitCode).filter(Boolean)));
    if (availableUnitCodes.length && next.length === availableUnitCodes.length) {
        next = [];
    }
    setRecruitingUnitCodes(next, true);
    closeRecruitingUnitModal();
    renderPatientTable();
    updateFilterCounts();
}

function loadRecruitingUnitState() {
    loadAvailableUnitCodes();
    loadRecruitingUnitSelection();
    renderRecruitingUnitOptions();
    updateRecruitingUnitSummary();
}

function resetRecruitingUnitState() {
    availableUnitCodes = [];
    setRecruitingUnitCodes([]);
    renderRecruitingUnitOptions();
    updateRecruitingUnitSummary();
    closeRecruitingUnitModal();
}

function isUnitFilterActive() {
    return recruitingUnitCodes.length > 0;
}

function getPatientUnitCode(patient = {}) {
    const selected = getDialysisUnitCanonical(patient);
    return normalizeUnitCode(getLocationCodeFromValue(selected));
}

function matchesUnitFilter(patient) {
    if (!patient) return false;
    if (!isUnitFilterActive()) return true;
    const code = getPatientUnitCode(patient);
    return code && recruitingUnitCodeSet.has(code);
}

function getPatientRandomizationCode(patient = {}) {
    return getLocationCodeFromValue(patient.location_at_randomization || patient.location);
}

function extractStudySite(studyId = '') {
    if (!studyId) return '';
    const parts = studyId.split('-');
    return (parts[1] || '').toUpperCase();
}

function getMostRecentLocationSortValue(patient = {}) {
    const info = getMostRecentLocationInfo(patient);
    if (!info.value) {
        return `zzz-${(patient.patient_name || '').toLowerCase()}`;
    }
    return formatLocationDisplay(info.value).toLowerCase();
}

function getLocationSourceLabel(source) {
    return LOCATION_SOURCE_LABELS[source] || '';
}

function setFilter(filter) {
    currentFilter = filter;
    FILTERS.forEach(({ key, buttonId }) => {
        const el = $(buttonId);
        if (el) {
            el.classList.toggle('active', key === filter);
        }
    });
    renderPatientTable();
}

function updateFilterCounts() {
    const filteredPatients = patientsData.filter(matchesUnitFilter);
    const counts = {
        all: filteredPatients.length,
        missing: 0,
        pending: 0,
        ready_notify: 0,
        waiting: 0,
        final_eligibility: 0,
        ready_randomize: 0,
        randomized_np: 0,
        randomized_rx: 0,
        ineligible: 0,
        opted_out: 0,
        notes: 0
    };

    filteredPatients.forEach(patient => {
        const flags = patient.bucketFlags || computeBucketFlags(patient);
        if (flags.missing) counts.missing++;
        if (flags.pending || (flags.missing && !flags.ineligible)) counts.pending++;
        if (flags.ready_notify) counts.ready_notify++;
        if (flags.waiting) counts.waiting++;
        if (flags.final_eligibility) counts.final_eligibility++;
        if (flags.ready_randomize) counts.ready_randomize++;
        if (flags.randomized_np) counts.randomized_np++;
        if (flags.randomized_rx) counts.randomized_rx++;
        if (flags.ineligible) counts.ineligible++;
        if (flags.opted_out) counts.opted_out++;
        if (flags.notes) counts.notes++;
    });

    FILTERS.forEach(({ key, countId }) => {
        const el = $(countId);
        if (!el) return;
        const value = key === 'all' ? counts.all : (counts[key] || 0);
        el.textContent = value;
    });
}

function showStatus(message, type = 'status') {
    const el = $('db-status');
    if (!el) return;
    el.textContent = message;
    el.classList.remove('status-success', 'status-error');
    if (type === 'success') {
        el.classList.add('status-success');
    } else if (type === 'error') {
        el.classList.add('status-error');
    }
}

function showToast(message, type = 'status') {
    const container = $('toast-root');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        if (toast.parentElement) {
            toast.parentElement.removeChild(toast);
        }
    }, 3000);
}

function isPatientLocked(patient) {
    return !!(patient && patient.locked_at);
}

function ensureEditablePatient(patient) {
    if (!patient) return false;
    if (isPatientLocked(patient)) {
        showStatus(READ_ONLY_MESSAGE, 'status');
        renderPatientTable();
        return false;
    }
    return true;
}

function showRecordWarning(message = '', type = 'error') {
    const el = $('record-warning');
    if (!el) return;
    if (!message) {
        el.textContent = '';
        el.classList.add('hidden');
        el.classList.remove('success');
        el.classList.remove('status');
        return;
    }
    el.textContent = message;
    el.classList.remove('hidden');
    el.classList.toggle('success', type === 'success');
    el.classList.toggle('status', type === 'status');
}

function copyTextToClipboard(value, label = 'Value') {
    if (!value) {
        showToast(`No ${label.toLowerCase()} to copy.`, 'error');
        return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value)
            .then(() => showToast(`${label} copied to clipboard.`, 'success'))
            .catch(() => fallbackCopy(value, label));
    } else {
        fallbackCopy(value, label);
    }
}

function fallbackCopy(value, label) {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        showToast(`${label} copied to clipboard.`, 'success');
    } catch (error) {
        console.error('Clipboard copy failed', error);
        showToast('Unable to copy to clipboard.', 'error');
    }
    document.body.removeChild(textarea);
}

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
window.updatePatientMrn = updatePatientMrn;
window.updatePatientHcn = updatePatientHcn;
window.deleteManualPatient = deleteManualPatient;
