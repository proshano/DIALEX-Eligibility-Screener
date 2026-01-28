# Quick Test Checklist

## Pre-Test Setup
- [ ] Chrome or Edge browser ready
- [ ] Test database file (V2 encrypted) available
- [ ] Network disabled (offline mode)
- [ ] Browser console open
- [ ] Two test user accounts with known passwords

---

## 1. Unlock/Login Flow

### Normal Login
- [ ] Load database → Login modal appears
- [ ] Enter valid username/password → Signs in successfully
- [ ] Status shows correct user name
- [ ] Patient data accessible

### Invalid Credentials
- [ ] Wrong password → Error message shows attempts remaining
- [ ] 3 failed attempts → Account locks, timer appears
- [ ] Lockout timer counts down correctly
- [ ] Change username → Lockout clears

### Unload Database
- [ ] Click "Unload database" → Database unloads
- [ ] Status shows "No database loaded"
- [ ] Can load new database

---

## 2. Recovery Mode Banner

### Banner Display
- [ ] Use central recovery password → Database unlocks
- [ ] Recovery banner visible: "Recovery mode is active..."
- [ ] Banner has correct ARIA attributes
- [ ] Normal login → Banner hidden

### Password Reset
- [ ] In recovery mode → Enter username
- [ ] Click "Reset password" → Central password prompt
- [ ] Enter central password → New password prompt
- [ ] Set new password (8+ chars) → Password resets
- [ ] Sign in with new password → Success
- [ ] Old password → No longer works

---

## 3. Legacy Removal

### Legacy Rejection
- [ ] Attempt to load legacy file → Error message
- [ ] Message: "Legacy encrypted databases are no longer supported"
- [ ] Database not loaded
- [ ] Application remains functional

### V2 Detection
- [ ] Load V2 database → Detects correctly
- [ ] Login modal appears
- [ ] No legacy errors

---

## 4. Integration Tests

### Complete Recovery Flow
- [ ] Central unlock → Recovery banner → Reset password → Sign in → Access granted

### Switch User
- [ ] Sign in as User A → Switch user → Sign in as User B → Access as User B

### Multiple User Lockout
- [ ] Lock User A → Switch to User B → User B can sign in

---

## 5. Edge Cases

- [ ] Empty username/password → Validation error
- [ ] Wrong central password → Error message
- [ ] Cancel in recovery mode → Appropriate behavior
- [ ] Database without central wrap → Error handled

---

## 6. Accessibility

- [ ] Tab through all fields → Logical order
- [ ] Enter submits form
- [ ] Escape closes modal (if allowed)
- [ ] Screen reader announces recovery banner

---

## 7. Browser Compatibility

- [ ] Chrome: All features work
- [ ] Edge: All features work
- [ ] No console errors in either browser

---

## Issues Found

_Record any problems here:_

1. 
2. 
3. 

---

## Test Results Summary

- **Date**: ___________
- **Tester**: ___________
- **Browser**: Chrome / Edge (version: _____)
- **OS**: ___________
- **Overall Status**: ✅ Pass / ❌ Fail / ⚠️ Partial

**Notes**: 
_________________________________________________
_________________________________________________
