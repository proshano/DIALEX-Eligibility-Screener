# AGENTS.md

This repository contains a self-contained, offline, browser-based screening tool for hospital environments.

## Priority Principles
- **Offline-first:** The app must run without internet access. Do not add network calls or dependencies that assume connectivity.
- **Self-contained:** No external CDN assets, remote fonts, or hosted libraries. Bundle everything locally in this repo.
- **No install step:** Users should be able to open the HTML file directly in a browser. Avoid build steps or package managers unless explicitly requested.
- **Robust & maintainable:** Prefer clear, explicit code with defensive checks and readable structure over clever shortcuts.
- **Stability over novelty:** Minimize changes that alter behavior; preserve existing flows unless a change is requested.
- **Non-technical users:** Assume end users are healthcare or health research staff with limited technical comfort. If a workflow should be avoided, remove or restrict the option rather than relying on instructions.

## Repository Structure
- `DIALEX_Recruitment_Tracker/` — The main recruitment tracker app (single HTML entry point with modular JS/CSS)
  - `DIALEX Recruitment Tracker App.html` — Entry point
  - `js/app/app-01.js` — Constants, configuration, save folder management
  - `js/app/app-02.js` — User management, authentication, autosave
  - `js/app/app-03.js` — Database setup, schema migration, patient loading, HCN validation, Study ID integrity
  - `js/app/app-04.js` — Patient table rendering, bucket flags, filter matching, UI handlers
  - `js/app/app-05.js` — Patient field persistence, Study ID assignment, CSV import
  - `js/app/app-06.js` — Date utilities, CSV parsing, location/unit management, recruiting unit filter
  - `js/app/app-boot.js` — DOM event listeners, initialization
  - `css/` — Stylesheets split by concern
- `DIALEX_Site_Recruitment_Setup/` — Setup app for creating site databases

## Implementation Guidelines
- Use plain HTML/CSS/JS (vanilla). Avoid frameworks and tooling that require internet access.
- Do not introduce telemetry, analytics, or external tracking.
- Store any needed data locally and avoid APIs. SQLite via sql.js runs in-browser with AES-GCM encryption.
- Ensure compatibility with Chrome and Edge (File System Access API required for autosave).
- JS files are loaded via script tags in order; all share the global scope.

## Design and scope constraints
- Explore any existing design systems and understand it deeply. 
- Implement EXACTLY and ONLY what the user requests.
- No extra features, no added components, no UX embellishments.
- Style aligned to the design system at hand. 
- Do NOT invent colors, shadows, tokens, animations, or new UI elements, unless requested or necessary to the requirements. 
- If any instruction is ambiguous, choose the simplest valid interpretation.


# Ucertainty and ambiguity
- If the question is ambiguous or underspecified, explicitly call this out and:
  - Ask up to 1–3 precise clarifying questions, OR
  - Present 2–3 plausible interpretations with clearly labeled assumptions.
- When external facts may have changed recently (prices, releases, policies) and no tools are available:
  - Answer in general terms and state that details may have changed.
- Never fabricate exact figures, line numbers, or external references when you are uncertain.
- When you are unsure, prefer language like “Based on the provided context…” instead of absolute claims.

## Output & Review
- Changes must be easy to audit: small, focused edits and clear variable/function names.
- If a change adds risk or assumes network availability, call it out and propose an offline alternative.

## Testing Expectations
- Prefer manual test steps that work offline (e.g., open `DIALEX_Screener_Standalone.html` in a browser and verify flows).
- Do not require installing tooling or packages to validate changes unless explicitly requested.
