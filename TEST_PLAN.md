# Test Plan: Unlock/Login Flow, Recovery Mode Banner, and Legacy Removal

## Overview
This document outlines manual test procedures for the new unlock/login flow, recovery mode banner, and legacy encryption removal. All tests are designed to be performed offline in Chrome or Edge.

## Prerequisites
- Chrome or Edge browser
- Test database files (multi-user encrypted V2 format)
- Optional: Legacy database file (for rejection testing)

---

## 1. Unlock/Login Flow Tests

### Test 1.1: Normal User Login
**Objective**: Verify standard username/password login works correctly.

**Steps**:
1. Open `DIALEX Recruitment Tracker App.html` in Chrome/Edge
2. Click "Load database"
3. Select a valid multi-user encrypted database file
4. Enter valid username and password
5. Click "Sign in"

**Expected Results**:
- Login modal appears with username and password fields
- "Sign in" button is enabled
- "Use central recovery password" button is visible
- "Unload database" button is visible
- After successful login, user is signed in and can access patient data
- Status shows "Signed in as: [Display Name] ([username])"

**Pass Criteria**: User successfully logs in and can access the application.

---

### Test 1.2: Invalid Username/Password
**Objective**: Verify error handling for incorrect credentials.

**Steps**:
1. Load database
2. Enter invalid username or password
3. Click "Sign in"

**Expected Results**:
- Error message appears: "Invalid username or password. X attempt(s) remaining."
- Password field is cleared and focused
- After 3 failed attempts, account is locked
- Lockout message shows remaining time (e.g., "Try again in 5m 00s")

**Pass Criteria**: Error messages display correctly and lockout activates after 3 attempts.

---

### Test 1.3: Account Lockout and Timer
**Objective**: Verify lockout mechanism and countdown timer.

**Steps**:
1. Load database
2. Enter valid username with wrong password 3 times
3. Observe lockout behavior
4. Wait for lockout to expire (or test with different user)

**Expected Results**:
- After 3 failed attempts, account is locked
- Password input is disabled
- Submit button is disabled
- Error message shows countdown timer updating every second
- Timer format: "Xm YYs" (minutes and seconds)
- After lockout expires, fields re-enable automatically

**Pass Criteria**: Lockout activates correctly and timer counts down accurately.

---

### Test 1.4: Username Input Clears Lockout Timer
**Objective**: Verify changing username clears lockout state.

**Steps**:
1. Trigger lockout on user A
2. Change username field to user B
3. Observe behavior

**Expected Results**:
- Lockout timer stops
- Error message clears
- Password field re-enables
- Submit button re-enables
- Password field is cleared

**Pass Criteria**: Username change clears lockout state.

---

### Test 1.5: Unload Database Button
**Objective**: Verify "Unload database" button works.

**Steps**:
1. Load database
2. Click "Unload database" button in login modal

**Expected Results**:
- Database is unloaded
- Login modal closes
- Status shows "No database loaded"
- "Load database" button becomes available again

**Pass Criteria**: Database unloads correctly.

---

## 2. Recovery Mode Banner Tests

### Test 2.1: Recovery Banner Display
**Objective**: Verify recovery mode banner appears when database is unlocked with central password.

**Steps**:
1. Load database
2. Click "Use central recovery password"
3. Enter correct central recovery password
4. Click "Unlock"
5. Observe login modal

**Expected Results**:
- Database decrypts successfully
- Login modal appears with recovery banner visible
- Banner text: "Recovery mode is active. Reset your password to continue signing in."
- Banner has `role="status"` and `aria-live="polite"` attributes
- Username and password fields are present
- "Reset password" button is visible

**Pass Criteria**: Recovery banner displays correctly with appropriate message.

---

### Test 2.2: Recovery Banner Hidden in Normal Login
**Objective**: Verify banner is hidden during normal login flow.

**Steps**:
1. Load database
2. Enter username and password (do not use recovery)

**Expected Results**:
- Login modal appears
- Recovery banner element has `hidden` class
- Banner is not visible to user
- Normal login flow proceeds

**Pass Criteria**: Banner is hidden during normal login.

---

### Test 2.3: Password Reset in Recovery Mode
**Objective**: Verify password reset works in recovery mode.

**Steps**:
1. Unlock database with central recovery password
2. Enter username in recovery mode login modal
3. Click "Reset password"
4. Enter central recovery password when prompted
5. Enter and confirm new password
6. Click "Reset password"
7. Sign in with new password

**Expected Results**:
- Central password prompt appears
- After verification, new password prompt appears
- Password must be at least 8 characters
- Password confirmation must match
- After reset, status shows "Password updated. Sign in with the new password."
- User can sign in with new password
- Old password no longer works

**Pass Criteria**: Password reset completes successfully and new password works.

---

### Test 2.4: Recovery Mode After Central Unlock
**Objective**: Verify recovery mode persists after central password unlock.

**Steps**:
1. Unlock database with central recovery password
2. Close login modal (if possible) or observe state
3. Verify recovery mode state persists

**Expected Results**:
- After central unlock, `handlePostLoadLogin` is called with `recoveryMode: true`
- Recovery banner remains visible until password is reset
- User cannot proceed without resetting password

**Pass Criteria**: Recovery mode state persists correctly.

---

## 3. Legacy Removal Tests

### Test 3.1: Legacy Database Rejection
**Objective**: Verify legacy encrypted databases are rejected.

**Steps**:
1. Attempt to load a legacy (non-V2) encrypted database file
2. Observe error handling

**Expected Results**:
- File reading completes
- Error status appears: "Legacy encrypted databases are no longer supported. Load a multi-user encrypted file."
- Database is not loaded
- Login modal does not appear
- Application remains in "not loaded" state

**Pass Criteria**: Legacy databases are rejected with clear error message.

---

### Test 3.2: V2 Database Detection
**Objective**: Verify V2 encrypted databases are detected correctly.

**Steps**:
1. Load a valid V2 encrypted database
2. Verify it loads successfully

**Expected Results**:
- File is recognized as V2 format
- `isV2EncryptedPayload()` returns true
- Login modal appears
- No legacy-related error messages

**Pass Criteria**: V2 databases are detected and loaded correctly.

---

### Test 3.3: Legacy Error in Decrypt Function
**Objective**: Verify `decryptDatabasePayload` rejects legacy format.

**Steps**:
1. If possible, test direct call to `decryptDatabasePayload` with legacy data
2. Or verify error path in code

**Expected Results**:
- Function checks `isV2EncryptedPayload(packedData)`
- If false, throws: "Legacy encrypted databases are no longer supported."
- Error is caught and displayed to user

**Pass Criteria**: Legacy format is rejected at decryption level.

---

## 4. Integration Tests

### Test 4.1: Complete Recovery Flow
**Objective**: Test end-to-end recovery scenario.

**Steps**:
1. Load database with central recovery password
2. Verify recovery banner appears
3. Enter username
4. Click "Reset password"
5. Verify central password
6. Set new password
7. Sign in with new password
8. Verify normal operation

**Expected Results**:
- All steps complete successfully
- User can access application after recovery
- Recovery banner disappears after password reset
- Normal login works with new password

**Pass Criteria**: Complete recovery flow works end-to-end.

---

### Test 4.2: Switch User Flow
**Objective**: Verify user switching works correctly.

**Steps**:
1. Sign in as user A
2. Click "Switch user"
3. Sign in as user B
4. Verify user B's access

**Expected Results**:
- "Switch user" button opens login modal with `allowCancel: true`
- User can cancel to stay signed in
- User can sign in as different user
- Status updates to show new user
- Audit log records both sign-out and sign-in events

**Pass Criteria**: User switching works correctly.

---

### Test 4.3: Lockout with Multiple Users
**Objective**: Verify lockout doesn't affect other users.

**Steps**:
1. Lock out user A (3 failed attempts)
2. Change username to user B
3. Enter correct password for user B
4. Verify user B can sign in

**Expected Results**:
- User A remains locked
- User B can sign in successfully
- Lockout timer for user A continues independently
- No cross-user lockout interference

**Pass Criteria**: Lockouts are user-specific.

---

## 5. Edge Cases and Error Handling

### Test 5.1: Empty Username/Password
**Objective**: Verify validation for empty fields.

**Steps**:
1. Load database
2. Leave username or password empty
3. Attempt to sign in

**Expected Results**:
- HTML5 validation prevents submission (if `required` attribute present)
- Or error message: "Username is required." / "Password is required."

**Pass Criteria**: Empty fields are validated.

---

### Test 5.2: Cancel During Recovery
**Objective**: Verify cancel behavior in recovery mode.

**Steps**:
1. Unlock with central password (recovery mode)
2. Attempt to cancel login modal

**Expected Results**:
- If `allowCancel: false`, cancel button/close button are hidden
- If `allowCancel: true`, cancel returns to previous state
- Recovery mode state may persist or reset appropriately

**Pass Criteria**: Cancel behavior is appropriate for context.

---

### Test 5.3: Incorrect Central Recovery Password
**Objective**: Verify error handling for wrong central password.

**Steps**:
1. Load database
2. Click "Use central recovery password"
3. Enter incorrect central password
4. Click "Unlock"

**Expected Results**:
- Error message: "Central recovery password is incorrect."
- Database remains locked
- User can retry or use regular login

**Pass Criteria**: Incorrect central password is handled gracefully.

---

### Test 5.4: Database Without Central Wrap
**Objective**: Verify behavior when central wrap is missing.

**Steps**:
1. Load database that lacks central recovery password setup
2. Attempt to use recovery password

**Expected Results**:
- Error message: "Central recovery password is unavailable for this database."
- Recovery option may be disabled or show error

**Pass Criteria**: Missing central wrap is handled correctly.

---

## 6. Accessibility Tests

### Test 6.1: Keyboard Navigation
**Objective**: Verify keyboard accessibility.

**Steps**:
1. Load database
2. Navigate login modal using only keyboard (Tab, Enter, Escape)

**Expected Results**:
- All interactive elements are focusable
- Tab order is logical
- Enter submits form
- Escape closes modal (if cancel allowed)
- Focus management works correctly

**Pass Criteria**: Full keyboard navigation works.

---

### Test 6.2: Screen Reader Support
**Objective**: Verify ARIA attributes and announcements.

**Steps**:
1. Use screen reader (NVDA/JAWS/VoiceOver)
2. Navigate login modal
3. Trigger recovery mode
4. Observe announcements

**Expected Results**:
- Recovery banner has `role="status"` and `aria-live="polite"`
- Error messages are announced
- Form labels are associated correctly
- Modal has appropriate ARIA attributes

**Pass Criteria**: Screen reader can navigate and understand state.

---

## 7. Browser Compatibility

### Test 7.1: Chrome Compatibility
**Objective**: Verify functionality in Chrome.

**Steps**:
1. Test all major flows in Chrome
2. Verify no console errors

**Expected Results**:
- All features work in Chrome
- No JavaScript errors
- File picker works
- Directory picker works (if supported)

**Pass Criteria**: Chrome compatibility confirmed.

---

### Test 7.2: Edge Compatibility
**Objective**: Verify functionality in Edge.

**Steps**:
1. Test all major flows in Edge
2. Verify no console errors

**Expected Results**:
- All features work in Edge
- No JavaScript errors
- File picker works
- Directory picker works

**Pass Criteria**: Edge compatibility confirmed.

---

## Test Data Requirements

### Valid Test Database
- Multi-user encrypted V2 format
- Contains at least 2 user accounts
- Has central recovery password configured
- Contains sample patient data

### Invalid Test Database
- Legacy encrypted format (if available)
- Or corrupted V2 file

### Test Users
- User A: Regular user account
- User B: Admin account
- Both with known passwords

---

## Test Execution Notes

1. **Offline Testing**: All tests should be performed with network disabled to verify offline-first behavior.

2. **Browser Console**: Keep browser console open to catch any JavaScript errors.

3. **Status Messages**: Pay attention to status bar messages for feedback on operations.

4. **Audit Log**: Check audit log entries (if accessible) to verify events are recorded correctly.

5. **File Persistence**: Verify that database files are saved/loaded correctly from local filesystem.

---

## Pass/Fail Criteria Summary

- **Pass**: All expected results occur, no errors in console, user can complete workflow
- **Fail**: Unexpected behavior, errors in console, workflow cannot be completed, or security issues

---

## Known Limitations

- Legacy database files may not be available for testing rejection
- Lockout timer requires waiting 5 minutes for full expiration test
- Some edge cases may require database manipulation that's not easily testable manually

---

## Reporting

For each test:
1. Record test number and name
2. Note pass/fail status
3. Document any deviations from expected results
4. Include screenshots if issues found
5. Note browser version and OS

---

## Maintenance

This test plan should be updated when:
- New features are added to login/recovery flow
- Error messages change
- Browser compatibility requirements change
- Security requirements evolve
