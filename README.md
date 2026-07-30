<p align="center">
  <img src="docs/screenshots/icon.png" alt="DMARC Viewer" width="96" height="96" />
</p>

<h1 align="center">DMARC Viewer</h1>

<p align="center">
  <a href="./README.md">English</a> ·
  <a href="./README.de.md">Deutsch</a>
</p>

<p align="center">
  Desktop app for fetching, importing, and analyzing DMARC aggregate reports.<br />
  IMAP mailbox or local files → KPIs, alignment charts, and detail tables.
</p>

<p align="center">
  <a href="https://github.com/codemacherUG/dmarcviewer/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/codemacherUG/dmarcviewer?label=release" /></a>
  <a href="https://github.com/codemacherUG/dmarcviewer/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/codemacherUG/dmarcviewer/total" /></a>
  <img alt="Platforms" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-1f6f8b" />
  <img alt="Electron" src="https://img.shields.io/badge/Electron-39-47848F?logo=electron&logoColor=white" />
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#screenshots">Screenshots</a> ·
  <a href="#download--installation">Download</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#development">Development</a>
</p>

---

## What does the app do?

DMARC aggregate reports (RUA) often land as XML/ZIP/GZ in a dedicated mailbox and are hard to read. **DMARC Viewer** fetches these emails via IMAP (or via file import), parses them locally, and shows at a glance:

- how many messages **passed** or **failed**, and which **dispositions** (`none` / `quarantine` / `reject`) were applied
- whether **DMARC, SPF, and DKIM alignment** hold
- which **sources (IPs)**, **From domains**, and **reporting organizations** stand out
- how volume and pass rate evolve **over time**
- optional **alerts** for rising failures, a low pass rate, or newly seen source IPs

Everything runs locally on your machine: credentials stay in the Electron `userData` folder, and the password is encrypted with `safeStorage`. There is no cloud account and no telemetry. The UI is available in **German** and **English**.

> **Note:** Only aggregate/RUA reports are analyzed. Failure/forensic reports (RUF) are not processed.

---

## Screenshots

### Dashboard

KPIs, alignment charts (including disposition), time series, filters, and a built-in DNS check for DMARC, SPF, and DKIM selectors:

![Dashboard with KPIs, alignment charts, and DNS check](docs/screenshots/dashboard.png)

### Aggregation & details

Reporting organizations, source IPs (including reverse DNS), From domains, individual reports, and record details — click a table row to drill down:

![Tables with organizations, IPs, domains, and report details](docs/screenshots/tables.png)

### Settings

Multiple IMAP accounts, auto-fetch, alerts (failures / pass-rate / new sources), ignore list, system tray, and UI language:

![Settings dialog with IMAP configuration](docs/screenshots/settings.png)

---

## Features

| Area | Details |
| --- | --- |
| **IMAP fetch** | Gmail, Outlook/Microsoft 365, or any IMAP server; incremental via UIDs |
| **Multiple accounts** | Any number of IMAP accounts/profiles with separate caches; custom display name (default: email domain); switch via toolbar |
| **File import** | XML, GZ, ZIP, EML/MIME — dialog or drag & drop |
| **Local cache** | Parsed reports are kept; subsequent fetches only load new messages |
| **Dashboard** | Reports, messages, pass/fail, pass rate, date range |
| **Charts** | Doughnuts for DMARC/SPF/DKIM alignment and disposition (none/quarantine/reject); volume & pass rate over time |
| **Tables** | Organizations, source IPs, From domains, individual reports + record details; click a row to filter |
| **IP enrichment** | Reverse DNS and detection of known senders (Google, Microsoft, Amazon SES, …) |
| **Filters** | Date range (7 / 30 / 90 days / all / custom), domain, plus drill-down by org, source IP, and From domain |
| **DNS check** | Live lookup of DMARC (`p`, `rua`), SPF, and DKIM selectors (auto-collected from reports or manual) |
| **Export** | Currently filtered data as CSV or JSON |
| **Auto-fetch** | Optional interval across all accounts + desktop notification when failures increase |
| **Alerts** | Pass-rate threshold (7 days) and "new source detected" with an ignore list for known IPs |
| **System tray** | Optionally keep running in the background; fetching and notifications continue with the window closed |
| **Autostart** | Optional launch at system login; with tray enabled the app can start hidden in the background |
| **Language** | Switchable German and English UI (Settings) |
| **Auto-update** | Checks GitHub Releases (NSIS, AppImage, macOS ZIP) |

---

## Download & installation

Ready-made builds are available under [GitHub Releases](https://github.com/codemacherUG/dmarcviewer/releases/latest):

| Platform | Packages |
| --- | --- |
| **Windows** | NSIS installer, portable EXE |
| **Linux** | AppImage, `.deb` |
| **macOS** | DMG and ZIP (x64 / arm64) |

Auto-update works in packaged builds (not in dev mode). Portable EXE and `.deb` are not updated automatically — NSIS setup, AppImage, and macOS ZIP are.

---

## Requirements

- For building from source: **Node.js 20+**
- For Gmail / Outlook: an **app password** (not your normal account password)

### App passwords & IMAP

| Provider | Host | Port | Notes |
| --- | --- | --- | --- |
| **Gmail** | `imap.gmail.com` | `993` (TLS) | Google Account → Security → 2-Step Verification → App passwords |
| **Outlook / Microsoft 365** | `outlook.office365.com` | `993` (TLS) | App password or enable IMAP if the tenant allows it |
| **Custom** | any | e.g. `993` | Username/password; TLS recommended |

Native Gmail API / Microsoft Graph OAuth are not included — IMAP covers the common providers.

---

## Usage

1. Open **Settings** → **IMAP account**, set provider/host/user/app password, and save. Add further accounts if needed.
2. Optionally set a short **display name** (empty = email domain, e.g. `codemacher.de`). **Test connection** if needed. Under **Fetch & notifications**, configure auto-fetch, alerts, system tray, autostart, and language.
3. In the main window, **Fetch reports** — or load XML/GZ/ZIP/EML via **Files** / drag & drop. With multiple accounts, switch via the account filter.
4. Narrow with date range (including custom From/To), domain, or by clicking a row in the org / IP / From tables; review charts and tables; export if needed.
5. Cross-check domains in the **DNS check** (policy `p`, reporting URI `rua`, SPF, and DKIM selectors from the reports or entered manually).

### Alerts & background mode

- **New failures** — desktop notification when the failing message count rises after a fetch.
- **Pass-rate alert** — notify when the 7-day pass rate falls below a configured threshold (0 = off).
- **New source** — notify when a previously unseen source IP appears; list known IPs (or prefixes like `66.249.*`) under ignored sources to suppress noise.
- **System tray** — optionally keep the app running when the window is closed so auto-fetch and notifications continue. Tray menu: show window, fetch now, quit.
- **Autostart** — optionally launch at system login; combined with the tray the app can start hidden in the background.

### Typical flow

```text
IMAP mailbox(es) / local files
        │
        ▼
  Parse (XML / GZ / ZIP / EML)
        │
        ▼
  Local cache per account (userData)
        │
        ▼
  Analysis → KPIs, charts, tables
        │
        ├── Filters (date range, domain, org / IP / From drill-down)
        ├── DNS check (DMARC / SPF / DKIM)
        ├── Alerts (failures / pass rate / new sources)
        └── Export (CSV / JSON)
```

---

## Development

```bash
npm install
npm run dev
```

Run unit tests (filter / aggregation logic):

```bash
npm test
```

Production build locally:

```bash
npm run build
npm start
```

Platform packages:

```bash
npm run build:linux   # AppImage + deb
npm run build:win     # NSIS + portable
npm run build:mac     # DMG/ZIP (macOS only)
```

GitHub release (all platforms via Actions): push a tag like `v1.0.5` or start the **Release** workflow manually.

### Stack

- **Electron** + **electron-vite** + **TypeScript**
- IMAP: [`imapflow`](https://github.com/postalsys/imapflow)
- Parsing: [`@koduhai/dmarc-parser`](https://www.npmjs.com/package/@koduhai/dmarc-parser)
- Charts: [Chart.js](https://www.chartjs.org/)
- Updates: [`electron-updater`](https://www.electron.build/auto-update) via GitHub Releases
- Tests: [Vitest](https://vitest.dev/)

---

## Notes & limitations

- Failure/RUF reports are not analyzed.
- Messages without a valid DMARC attachment are skipped and counted.
- Settings and report caches live under the Electron `userData` path (not in the repo); each IMAP account has its own cache.
- Clear cache: Settings → IMAP account → **Clear this account’s cache** (the next fetch will retrieve everything again for that account).
- Optionally, fetched messages can be marked as read (`\Seen`).
- With system tray enabled, closing the window hides the app instead of quitting — use **Quit** from the tray menu to exit fully.
- Existing single-account settings from older versions are migrated automatically to the multi-account format.

---

## Author

**codemacher UG (haftungsbeschränkt)** · [codemacher.de](https://codemacher.de/)

Issues and pull requests welcome on [GitHub](https://github.com/codemacherUG/dmarcviewer).
