#!/usr/bin/env node
// Standalone test for computeBucketFlags study ID gating logic.
// Run: node test-bucket-logic.js
// Not committed to git.

const assert = require('node:assert');

// --- Minimal stubs for globals used by computeBucketFlags ---

const DIABETES_STATUS = { UNKNOWN: 0, NO: -1, YES: 1 };
const OPT_OUT_STATUS = { PENDING: 'pending', DID_NOT: 'did_not_opt_out', OPTED_OUT: 'opted_out' };
const NOTIFICATION_BUFFER_DAYS = 15;

let availableUnitCodes = [];

const PRIMARY_BUCKET_ORDER = [
    'missing', 'opted_out', 'ineligible', 'randomized_rx', 'randomized_np',
    'ready_randomize', 'final_eligibility', 'waiting', 'ready_notify', 'pending'
];

function normalizeProvinceCode(v) { return String(v || '').trim().toUpperCase(); }
function isProvinceTerritoryCode(v) { return ['ON','AB','BC','SK','MB','QC','NB','NS','PE','NL','NT','YT','NU'].includes(normalizeProvinceCode(v)); }
function isIneligibleHealthCardValue(hcn, prov) {
    const n = String(hcn || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    if (!n) return false;
    if (/^[A-Z]{4}[0-9]{8}$/.test(n)) return true;
    return normalizeProvinceCode(prov) === 'QC';
}
function validateHealthCardFormat() { return ''; }
function normalizeDiabetesStatus(v) { return Number(v) || 0; }
function normalizeLocationValue(v) { return String(v || '').trim().toLowerCase(); }
function normalizeUnitCode(v) { return (v || '').trim().toUpperCase(); }
function getLocationCodeFromValue(v) {
    const n = normalizeLocationValue(v);
    if (!n) return '';
    if (n.includes(':')) return n.split(':')[0].trim().toUpperCase();
    return (n.split(/\s+/)[0] || '').toUpperCase();
}
function getDialysisUnitCanonical(p) {
    if (p.incl_incentre_hd !== 1) return '';
    return p.location_at_randomization || p.location || '';
}
function getCanonicalLocationValue(v) { return v || ''; }
function startOfToday() { const d = new Date(); d.setHours(0,0,0,0); return d; }
function parseISODate(v) { if (!v) return null; const d = new Date(v); return isNaN(d) ? null : d; }
function addDays(d, n) { const r = new Date(d); r.setDate(r.getDate() + n); return r; }

function determinePrimaryBucket(flags) {
    for (const key of PRIMARY_BUCKET_ORDER) {
        if (flags[key]) return key;
    }
    return 'all';
}

// --- Copy of computeBucketFlags from app-04.js ---

function computeBucketFlags(patient = {}) {
    const flags = {
        missing: false, pending: false, ready_notify: false, waiting: false,
        final_eligibility: false, ready_randomize: false, randomized_np: false,
        randomized_rx: false, ineligible: false, opted_out: false, notes: false,
        primary: 'all'
    };
    if (!patient) return flags;

    const hasHealthCard = Boolean(String(patient.health_card || '').trim());
    const hcnProvince = normalizeProvinceCode(patient.health_card_province || '');
    const invalidProvince = hcnProvince && !isProvinceTerritoryCode(hcnProvince);
    const hcnIneligible = invalidProvince || isIneligibleHealthCardValue(patient.health_card, hcnProvince);
    const ageValue = Number.isFinite(patient.age) ? patient.age : null;
    const missingAge = !Number.isFinite(ageValue);
    const needsDiabetesStatus = Number.isFinite(ageValue) && ageValue >= 45 && ageValue < 60;
    const diabetesStatus = normalizeDiabetesStatus(patient.diabetes_known);
    const missingDiabetes = needsDiabetesStatus && diabetesStatus === DIABETES_STATUS.UNKNOWN;
    const ageIneligible = !missingAge && !missingDiabetes && Number.isFinite(ageValue)
        ? (ageValue < 45 || (needsDiabetesStatus && diabetesStatus === DIABETES_STATUS.NO))
        : false;
    const requiresDialysisUnit = patient.incl_incentre_hd === 1;
    const locationValue = requiresDialysisUnit ? getDialysisUnitCanonical(patient) : '';
    const hasDialysisUnit = requiresDialysisUnit && Boolean(normalizeLocationValue(locationValue));
    const hasDialysisHistory = Boolean(patient.dialysis_start_date) || Boolean(patient.dialysis_duration_confirmed);
    const dialysisIneligible = hasDialysisHistory && Number(patient.incl_dialysis_90d) !== 1;
    const inCentreIneligible = Number(patient.incl_incentre_hd) !== 1;
    const missingHcnInfo = (!hasHealthCard && !invalidProvince) || (hasHealthCard && !hcnProvince);
    const hcnFormatError = hasHealthCard ? validateHealthCardFormat(patient.health_card, hcnProvince || '') : '';
    const hcnMissingError = !!hcnFormatError && !hcnIneligible;
    const missingData = missingAge || missingDiabetes || missingHcnInfo || hcnMissingError || (requiresDialysisUnit && !hasDialysisUnit) || !hasDialysisHistory;

    const optOutStatus = patient.opt_out_status || OPT_OUT_STATUS.PENDING;
    const isOptedOutStatus = optOutStatus === OPT_OUT_STATUS.OPTED_OUT;
    flags.opted_out = isOptedOutStatus;
    const hasAnyExclusion = patient.hasAnyExclusion || false;
    const hasNonMissingIneligible = isOptedOutStatus || hasAnyExclusion || hcnIneligible || ageIneligible || dialysisIneligible || inCentreIneligible;
    flags.ineligible = hasNonMissingIneligible;
    flags.missing = !hasNonMissingIneligible && !hcnIneligible && missingData;

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

    const unitCode = hasDialysisUnit ? normalizeUnitCode(getLocationCodeFromValue(locationValue)) : '';
    const unitHasStudyIds = !unitCode || (Array.isArray(availableUnitCodes) && availableUnitCodes.map(normalizeUnitCode).indexOf(unitCode) >= 0);
    flags.noStudyIdsForUnit = !unitHasStudyIds && Boolean(unitCode);

    if (notMissingOrIneligible) {
        if (!hasNotification) {
            if (patient.inclusionMet && !hasAnyExclusion) {
                if (hasConfirmedNoExclusions) {
                    if (unitHasStudyIds) {
                        flags.ready_notify = true;
                    } else {
                        flags.pending = true;
                    }
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

// --- Helper to build a fully-eligible patient ---

function makeEligiblePatient(unitLocation, overrides = {}) {
    return {
        age: 65,
        health_card: '1234567890',
        health_card_province: 'ON',
        incl_incentre_hd: 1,
        incl_dialysis_90d: 1,
        dialysis_start_date: '2025-01-01',
        dialysis_duration_confirmed: 1,
        location: unitLocation,
        location_at_randomization: '',
        inclusionMet: true,
        noExclusions: true,
        hasAnyExclusion: false,
        no_exclusions_confirmed: 1,
        hasHealthCard: true,
        diabetes_known: DIABETES_STATUS.YES,
        opt_out_status: OPT_OUT_STATUS.PENDING,
        notification_date: '',
        randomized: 0,
        therapy_prescribed: 0,
        ...overrides
    };
}

// --- Tests ---

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        passed++;
        console.log(`  PASS  ${name}`);
    } catch (e) {
        failed++;
        console.log(`  FAIL  ${name}`);
        console.log(`        ${e.message}`);
    }
}

console.log('\n=== computeBucketFlags: Study ID gating ===\n');

test('Patient at unit WITH study IDs → ready_notify', () => {
    availableUnitCodes = ['SLH', 'TGH'];
    const p = makeEligiblePatient('SLH: St. Lukes Hospital');
    const flags = computeBucketFlags(p);
    assert.strictEqual(flags.primary, 'ready_notify');
    assert.strictEqual(flags.ready_notify, true);
    assert.strictEqual(flags.noStudyIdsForUnit, false);
});

test('Patient at unit WITHOUT study IDs → pending + noStudyIdsForUnit', () => {
    availableUnitCodes = ['SLH', 'TGH'];
    const p = makeEligiblePatient('OTH: Other Hospital');
    const flags = computeBucketFlags(p);
    assert.strictEqual(flags.primary, 'pending');
    assert.strictEqual(flags.pending, true);
    assert.strictEqual(flags.ready_notify, false);
    assert.strictEqual(flags.noStudyIdsForUnit, true);
});

test('Patient at unit WITHOUT study IDs, after importing IDs for that unit → ready_notify', () => {
    availableUnitCodes = ['SLH', 'TGH', 'OTH'];
    const p = makeEligiblePatient('OTH: Other Hospital');
    const flags = computeBucketFlags(p);
    assert.strictEqual(flags.primary, 'ready_notify');
    assert.strictEqual(flags.ready_notify, true);
    assert.strictEqual(flags.noStudyIdsForUnit, false);
});

test('No study IDs loaded at all → pending + noStudyIdsForUnit', () => {
    availableUnitCodes = [];
    const p = makeEligiblePatient('SLH: St. Lukes Hospital');
    const flags = computeBucketFlags(p);
    assert.strictEqual(flags.primary, 'pending');
    assert.strictEqual(flags.pending, true);
    assert.strictEqual(flags.noStudyIdsForUnit, true);
});

test('Patient with notification date at unit without study IDs → noStudyIdsForUnit flag set', () => {
    availableUnitCodes = ['TGH'];
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const dateStr = thirtyDaysAgo.toISOString().slice(0, 10);
    const p = makeEligiblePatient('SLH: St. Lukes Hospital', {
        notification_date: dateStr,
        opt_out_status: OPT_OUT_STATUS.DID_NOT,
        did_not_opt_out: 1,
        first_ready_date: new Date(thirtyDaysAgo.getTime() + NOTIFICATION_BUFFER_DAYS * 86400000)
    });
    const flags = computeBucketFlags(p);
    assert.strictEqual(flags.noStudyIdsForUnit, true);
    // Patient should still progress through post-notification states
    assert.strictEqual(flags.pending, false, 'should not be pending post-notification');
});

test('Missing data patient → missing flag regardless of study IDs', () => {
    availableUnitCodes = [];
    const p = makeEligiblePatient('SLH: St. Lukes Hospital', { age: undefined });
    const flags = computeBucketFlags(p);
    assert.strictEqual(flags.missing, true);
    assert.strictEqual(flags.pending, false);
});

test('Ineligible patient → ineligible flag regardless of study IDs', () => {
    availableUnitCodes = [];
    const p = makeEligiblePatient('SLH: St. Lukes Hospital', { incl_incentre_hd: 0 });
    const flags = computeBucketFlags(p);
    assert.strictEqual(flags.ineligible, true);
    assert.strictEqual(flags.pending, false);
});

test('No exclusions not confirmed → pending (not study ID issue)', () => {
    availableUnitCodes = ['SLH'];
    const p = makeEligiblePatient('SLH: St. Lukes Hospital', { no_exclusions_confirmed: 0 });
    const flags = computeBucketFlags(p);
    assert.strictEqual(flags.primary, 'pending');
    assert.strictEqual(flags.noStudyIdsForUnit, false);
});

test('Case insensitive unit code matching', () => {
    availableUnitCodes = ['slh'];
    const p = makeEligiblePatient('SLH: St. Lukes Hospital');
    const flags = computeBucketFlags(p);
    assert.strictEqual(flags.primary, 'ready_notify');
    assert.strictEqual(flags.noStudyIdsForUnit, false);
});

// --- Summary ---

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
