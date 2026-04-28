# DIALEX Recruitment Tracker

This repository contains the offline recruitment tracking tools for the **DIALEX** study: **DIALysis With EXpanded Solute Removal**, a pragmatic randomized trial evaluating expanded hemodialysis compared with conventional high-flux hemodialysis.

Study links:

- DIALEX study website: [https://dialex.study](https://dialex.study)
- ClinicalTrials.gov registration: [NCT06660277](https://clinicaltrials.gov/study/NCT06660277)

## What This Tracker Does

The DIALEX Recruitment Tracker is a browser-based tool for participating dialysis sites. It supports the local recruitment workflow from imported screening lists through notification, opt-out tracking, Study ID assignment, randomization, and prescribing status.

The tracker helps sites:

- import patient lists for pre-screening;
- assess DIALEX inclusion and exclusion criteria;
- document notification dates and the opt-out period;
- record opt-out status and opt-out dates;
- identify patients ready for final eligibility assessment and randomization;
- assign site Study IDs from the locally loaded Study ID list;
- track randomized patients and whether the assigned therapy has been prescribed;
- export lightweight recruitment summary reports.

The tool is intended for study operations. It is not a clinical decision support system and should not replace clinical judgment, source documentation, or the trial protocol.

## Design

The tracker is designed for hospital research workflows where internet access may be restricted or unavailable.

- **Offline-first:** the app runs locally in Chrome or Edge without external network calls.
- **Self-contained:** the distributable ZIP includes the HTML, CSS, JavaScript, and bundled browser libraries needed to run the tool.
- **Local encrypted storage:** site data are stored in an encrypted local database file.
- **Autosave support:** the app continuously writes rotating encrypted backups to the selected save folder.
- **Backward compatibility:** saved site databases are treated as production data and must remain loadable across releases.

## Repository Contents

- `DIALEX_Recruitment_Tracker/` contains the main recruitment tracker app.
- `DIALEX_Site_Recruitment_Setup/` contains the setup tool used to prepare site recruitment databases.
- `AGENTS.md` documents development constraints and compatibility rules for future changes.

## Using a Release

End users should download the latest recruitment tracker ZIP from the repository's [GitHub Releases](https://github.com/proshano/DIALEX-Recruitment-Tracker/releases), extract the ZIP, and open:

`DIALEX_Recruitment_Tracker/DIALEX Recruitment Tracker App.html`

Use Google Chrome or Microsoft Edge. The tool relies on browser APIs used for local encrypted file handling and autosave support.

Release ZIP files are attached to GitHub Releases rather than stored in the source tree.

## Development Notes

This is a plain HTML/CSS/JavaScript application. There is no build step and no package installation requirement for routine use.

When changing the tracker:

- preserve compatibility with existing encrypted site databases;
- avoid network dependencies, telemetry, remote fonts, and CDN assets;
- keep changes focused on the recruitment workflow;
- verify that the browser app still opens directly from the release folder;
- attach release ZIPs to GitHub Releases, not to the repository root.
