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

- how many messages **passed** or **failed**
- whether **DMARC, SPF, and DKIM alignment** hold
- which **sources (IPs)**, **From domains**, and **reporting organizations** stand out
- how volume and pass rate evolve **over time**

Everything runs locally on your machine: credentials stay in the Electron `userData` folder, and the password is encrypted with `safeStorage`. There is no cloud account and no telemetry.

> **Note:** Only aggregate/RUA reports are analyzed. Failure/forensic reports (RUF) are not processed.

---

## Screenshots

### Dashboard

KPIs, alignment charts, time series, and a built-in DNS check for DMARC and SPF records:

![Dashboard with KPIs, alignment charts, and DNS check](docs/screenshots/dashboard.png)

### Aggregation & details

Reporting organizations, source IPs (including reverse DNS), From domains, individual reports, and record details:

![Tables with organizations, IPs, domains, and report details](docs/screenshots/tables.png)

### Settings

IMAP access (Gmail, Outlook/Microsoft 365, or custom), folders, subject filters, auto-fetch, and notifications:

![Settings dialog with IMAP configuration](docs/screenshots/settings.png)

---

## Features

| Area | Details |
| --- | --- |
| **IMAP fetch** | Gmail, Outlook/Microsoft 365, or any IMAP server; incremental via UIDs |
| **File import** | XML, GZ, ZIP, EML/MIME — dialog or drag & drop |
| **Local cache** | Parsed reports are kept; subsequent fetches only load new messages |
| **Dashboard** | Reports, messages, pass/fail, pass rate, date range |
| **Charts** | Doughnut for DMARC/SPF/DKIM alignment; volume & pass rate over time |
| **Tables** | Organizations, source IPs, From domains, individual reports + record details |
| **IP enrichment** | Reverse DNS and detection of known senders (Google, Microsoft, Amazon SES, …) |
| **Filters** | Date range (7 / 30 / 90 days / all) and domain |
| **DNS check** | Live lookup of DMARC (`p`, `rua`) and SPF |
| **Export** | Currently filtered data as CSV or JSON |
| **Auto-fetch** | Optional interval + desktop notification when failures increase |
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

1. Open **Settings**, set provider/host/user/app password, and save.
2. Optionally **Test connection**.
3. In the main window, **Fetch reports** — or load XML/GZ/ZIP/EML via **Open files** / drag & drop.
4. Narrow with date-range and domain filters, review charts and tables, export if needed.
5. Cross-check domains in the **DNS check** (policy `p`, reporting URI `rua`, SPF).

### Typical flow

```text
IMAP mailbox / local files
        │
        ▼
  Parse (XML / GZ / ZIP / EML)
        │
        ▼
  Local cache (userData)
        │
        ▼
  Analysis → KPIs, charts, tables
        │
        ├── Filters (date range, domain)
        ├── DNS check
        └── Export (CSV / JSON)
```

---

## Development

```bash
npm install
npm run dev
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

---

## Notes & limitations

- Failure/RUF reports are not analyzed.
- Messages without a valid DMARC attachment are skipped and counted.
- Settings and report cache live under the Electron `userData` path (not in the repo).
- Clear cache: Settings → **Clear cache** (the next fetch will retrieve everything again).
- Optionally, fetched messages can be marked as read (`\Seen`).

---

## Author

**codemacher UG (haftungsbeschränkt)** · [codemacher.de](https://codemacher.de/)

Issues and pull requests welcome on [GitHub](https://github.com/codemacherUG/dmarcviewer).
