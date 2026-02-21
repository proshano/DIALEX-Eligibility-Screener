DIALEX Recruitment Tracker - Read Me First

Repository folder name: DIALEX Recruitment Tracker

IMPORTANT: To use this tool, open ONLY the file named DIALEX Recruitment Tracker App.html in Google Chrome or Microsoft Edge.
Do not open or delete any other files.

How to open the tool
1) Use Chrome or Edge.
2) Find the DIALEX_Recruitment_Tracker folder.
3) Double-click DIALEX Recruitment Tracker App.html.

Do NOT open or delete these
- the css folder and the files inside it
- the js folder and the files inside it

If you see a message that the browser is not supported, close the window and reopen DIALEX Recruitment Tracker App.html in Chrome or Edge.

Offline reminder
When copying this tool to another computer, copy the entire DIALEX_Recruitment_Tracker folder.

Recruitment summary export
- In the Patient data section, use "Export recruitment summary (.csv)" to download a CSV report.
- The export includes: notified patients, in opt-out period, opt-out period ended with opt-out status not documented, opted out, did not opt-out but deemed ineligible for another reason after notification, did not opt out and waiting to be randomized, randomized not yet prescribed, and randomized and prescribed.
- Counts are shown for each recruitment state, and percentages are based on notified patients.

Randomization and record locking
- When a patient is marked as randomized, the record is locked automatically.
- For randomized patients, eligibility/recruitment fields are restricted to admin users.
- Allocation and Prescribed remain editable for randomized records, including when the record is locked.
- Only admin users can unlock records.
- Unlocking any record requires re-entering the signed-in user's password.

Password management updates
- Signed-in users can use "Change my password" for their own account.
- If an admin resets another user's password, it is temporary.
- A user with a temporary password must first sign in with that temporary password, then set a new password.

Operator test checklist (offline)
1) Open `DIALEX Recruitment Tracker App.html` in Chrome or Edge.
2) Load and unlock a test database.
3) Mark one patient as randomized and confirm the record auto-locks.
4) As a non-admin user, try editing eligibility/recruitment fields on that randomized patient (they should appear disabled).
5) As a non-admin user, verify a locked record cannot be unlocked.
6) As a non-admin user, confirm Allocation + Prescribed can still be edited on a randomized record.
7) As an admin user, unlock a record and confirm re-authentication is required.
8) Enter a notification date before dialysis start date (or dialysis start date after notification date) and confirm a validation error appears.
9) Export `Export recruitment summary (.csv)` and confirm the file includes count and `Percent of notified` columns.
