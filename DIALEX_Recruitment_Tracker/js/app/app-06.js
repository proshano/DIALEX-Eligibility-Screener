
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
const DOB_WARNING_YEARS = 100;
const DIALYSIS_WARNING_YEARS = 10;
const NOTIFICATION_WARNING_DAYS = 30;

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

function getTorontoTodayParts() {
    const parts = getTorontoDateParts();
    return {
        year: parts.year,
        month: parts.month,
        day: parts.day
    };
}

function getTorontoTodayUtcMs() {
    const today = getTorontoTodayParts();
    return Date.UTC(today.year, today.month - 1, today.day);
}

function getDateUtcMs(date) {
    return Date.UTC(date.getFullYear(), date.getMonth(), date.getDate());
}

function getTorontoNowTimestamp() {
    return getTorontoNow().getTime();
}

function isDateOlderThanYears(date, years) {
    if (!date || !Number.isFinite(years)) return false;
    const today = getTorontoTodayParts();
    const cutoffYear = today.year - years;
    const dateYear = date.getFullYear();
    if (dateYear < cutoffYear) return true;
    if (dateYear > cutoffYear) return false;
    const dateMonth = date.getMonth() + 1;
    if (dateMonth < today.month) return true;
    if (dateMonth > today.month) return false;
    return date.getDate() < today.day;
}

function isDateOlderThanDays(date, days) {
    if (!date || !Number.isFinite(days)) return false;
    const diff = getTorontoTodayUtcMs() - getDateUtcMs(date);
    if (Number.isNaN(diff)) return false;
    const diffDays = Math.floor(diff / MS_PER_DAY);
    return diffDays > days;
}

function buildDateFromParts(year, month, day) {
    if (!Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day)) return null;
    if (month < 1 || month > 12 || day < 1 || day > 31) return null;
    const date = new Date(0);
    date.setFullYear(year, month - 1, day);
    date.setHours(0, 0, 0, 0);
    if (Number.isNaN(date.getTime())) return null;
    if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day) {
        return null;
    }
    return date;
}

function resolveTwoDigitYear(value) {
    const year = Number(value);
    if (!Number.isFinite(year)) return null;
    if (year >= 100) return year;
    const current = getTorontoTodayParts().year % 100;
    return (year <= current ? 2000 : 1900) + year;
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
    const [first, second, third] = parts;
    let day, month, year;
    if (first > 1900) {
        year = first;
        month = second;
        day = third;
    } else if (third > 1900 || (third >= 0 && third < 100)) {
        year = resolveTwoDigitYear(third);
        day = first;
        month = second;
    } else {
        return null;
    }
    return buildDateFromParts(year, month, day);
}

function normalizeLegacyDate(value) {
    const date = parseLegacyDate(value);
    return date ? formatISODate(date) : '';
}

function calculateAgeFromDate(date) {
    if (!date) return null;
    const today = getTorontoTodayParts();
    let age = today.year - date.getFullYear();
    const month = date.getMonth() + 1;
    if (today.month < month || (today.month === month && today.day < date.getDate())) {
        age--;
    }
    return age;
}

function buildBirthDateFromAge(age) {
    if (!Number.isFinite(age)) return null;
    const today = getTorontoTodayParts();
    const year = today.year - Math.floor(age);
    let month = today.month;
    let day = today.day;
    let date = buildDateFromParts(year, month, day);
    while (!date && day > 1) {
        day -= 1;
        date = buildDateFromParts(year, month, day);
    }
    if (date) return date;
    return buildDateFromParts(year, 1, 1);
}

function normalizeHealthCardValue(value = '') {
    return String(value || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}

function inferProvinceFromHealthCard(value) {
    const normalized = normalizeHealthCardValue(value || '');
    if (/^M[0-9]{8}$/.test(normalized)) {
        return 'CF';
    }
    if (/^R[0-9]{8}$/.test(normalized)) {
        return 'RCMP';
    }
    if (/^K[0-9]{7}$/.test(normalized)) {
        return 'VAC';
    }
    if (/^[A-Z]{4}[0-9]{8}$/.test(normalized)) {
        return 'QC';
    }
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
        const provinceRaw = getField(row, [HCN_PROVINCE_HEADER]) || '';
        const provinceCode = normalizeProvinceCode(provinceRaw);
        const invalidProvince = provinceCode && !isProvinceTerritoryCode(provinceCode);
        const hcnFormatError = healthCard ? validateHealthCardFormat(healthCard, provinceCode) : '';
        const birthDate = parseLegacyDate(getField(row, [BIRTH_DATE_HEADER]));
        const dialysisStart = parseLegacyDate(getField(row, [START_DATE_HEADER]));
        let modalityCode = getField(row, [MODALITY_HEADER, 'Current Modality', 'Latest Modality']) || '';
        if (!VALID_MODALITY_CODES.includes(modalityCode) && DISPLAY_TO_PREFERRED_CODE[modalityCode]) {
            modalityCode = DISPLAY_TO_PREFERRED_CODE[modalityCode];
        }
        const hasValidModality = VALID_MODALITY_CODES.includes(modalityCode);
        const diabetesStatus = resolveDiabetesStatus(
            getField(row, [DIAB_TYPE1_HEADER]),
            getField(row, [DIAB_TYPE2_HEADER])
        );
        const hasDiabetes = diabetesStatus === DIABETES_STATUS.YES;
        const age = calculateAgeFromDate(birthDate);
        const daysOnDialysis = calculateDaysOnDialysis(dialysisStart);
        const reasons = [];

        if (!healthCard && !invalidProvince) {
            summary.breakdown.missingHealthCard++;
            reasons.push('Missing health card number');
        }
        if (invalidProvince) {
            reasons.push('Invalid HCN province/territory');
        } else if (hcnFormatError) {
            reasons.push(hcnFormatError);
        }
        if (!birthDate || !dialysisStart) {
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
    const diff = getTorontoTodayUtcMs() - getDateUtcMs(startDate);
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
    const diff = (getTorontoTodayUtcMs() - getDateUtcMs(start)) / MS_PER_DAY;
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
    if (firstEligible && firstEligible.getTime() > getTorontoNowTimestamp()) {
        issues.push(`Eligible on ${formatISODate(firstEligible)}`);
    }
    return issues;
}

function parseISODate(value) {
    if (!value) return null;
    const parts = value.split('-').map(Number);
    if (parts.length !== 3) return null;
    const [y, m, d] = parts;
    return buildDateFromParts(y, m, d);
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

function formatEntryDate(value) {
    if (!value) return '';
    const date = parseISODate(value) || parseLegacyDate(value);
    if (!date) return value;
    const d = String(date.getDate()).padStart(2, '0');
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const y = date.getFullYear();
    return `${d}/${m}/${y}`;
}

function formatDateEntryInput(value) {
    if (value === null || value === undefined) return '';
    const raw = String(value);
    if (raw.includes('-') || /^\d{4}\//.test(raw)) {
        return raw;
    }
    const digits = raw.replace(/\D/g, '').slice(0, 8);
    if (!digits) return '';
    if (digits.length <= 2) return digits;
    if (digits.length <= 4) return `${digits.slice(0, 2)}/${digits.slice(2)}`;
    return `${digits.slice(0, 2)}/${digits.slice(2, 4)}/${digits.slice(4)}`;
}

function formatFriendlyDate(value) {
    if (!value) return '';
    const date = parseISODate(value);
    if (!date) return '';
    const d = String(date.getDate()).padStart(2, '0');
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const y = date.getFullYear();
    return `${d}/${m}/${y}`;
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
    const isoMatch = trimmed.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (isoMatch) {
        const year = Number(isoMatch[1]);
        const month = Number(isoMatch[2]);
        const day = Number(isoMatch[3]);
        const resolvedYear = year < 100 ? resolveTwoDigitYear(year) : year;
        const date = buildDateFromParts(resolvedYear, month, day);
        return date ? formatISODate(date) : '';
    }
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
    const today = getTorontoTodayParts();
    return new Date(today.year, today.month - 1, today.day);
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
    const hasAvailableUnits = !!(db && Array.isArray(availableUnitCodes) && availableUnitCodes.length);
    const shouldMarkUnavailable = hasAvailableUnits;
    const allowedSet = hasAvailableUnits
        ? new Set(availableUnitCodes.map(normalizeUnitCode).filter(Boolean))
        : null;
    let selectedListed = false;

    LOCATION_OPTION_LIST.forEach(option => {
        if (db) {
            if (!hasAvailableUnits) {
                return;
            }
            const code = normalizeUnitCode(getLocationCodeFromValue(option.canonical));
            if (!code || !allowedSet.has(code)) {
                return;
            }
        }
        const selected = option.normalized === normalizedSelected ? ' selected' : '';
        if (selected) {
            selectedListed = true;
        }
        options.push(`<option value="${escapeHtml(option.canonical)}"${selected}>${escapeHtml(option.display)}</option>`);
    });
    if (normalizedSelected && !selectedListed) {
        const display = getLocationDisplayFromCanonical(selectedValue) || formatLocationDisplay(selectedValue) || selectedValue;
        const suffix = shouldMarkUnavailable ? ' (not in program)' : '';
        options.push(`<option value="${escapeHtml(selectedValue)}" selected>${escapeHtml(`${display}${suffix}`)}</option>`);
    } else if (db && !hasAvailableUnits) {
        options.push('<option value="" disabled>No program units loaded</option>');
    }
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
            VALUES (?, ?, ?)
        `);
        stmt.run([key, value, getSqlTimestamp()]);
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
