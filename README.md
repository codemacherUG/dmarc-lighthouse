# DMARC Viewer

Desktop-Tool (Electron / Node), das per **IMAP** DMARC-Aggregate-Reports aus einem Postfach holt, parst und in einer GUI anzeigt. Zusätzlich: lokaler Cache, Datei-Import, Filter, Export und DNS-Checks.

## Voraussetzungen

- Node.js 20+
- Für Gmail / Outlook: **App-Passwort** (nicht das normale Kontopasswort)

### App-Passwörter

- **Gmail:** Google-Konto → Sicherheit → 2-Schritt-Bestätigung → App-Passwörter. IMAP-Host: `imap.gmail.com`, Port `993`, TLS.
- **Outlook / Microsoft 365:** App-Passwort bzw. IMAP freigeben, sofern vom Tenant erlaubt. Host: `outlook.office365.com`, Port `993`, TLS.
- **Custom:** beliebiger IMAP-Server mit Benutzer/Passwort.

Native Gmail-API- / Microsoft-Graph-OAuth sind nicht enthalten — IMAP deckt die gängigen Anbieter ab.

## Start

```bash
npm install
npm run dev
```

Produktion:

```bash
npm run build
npm start
```

Plattform-Pakete:

```bash
npm run build:linux   # AppImage + deb
npm run build:win     # NSIS + portable (unter Linux ggf. eingeschränkt)
npm run build:mac     # DMG/ZIP (nur auf macOS)
```

GitHub Release (alle Plattformen via Actions): Tag `v1.0.4` pushen oder Workflow „Release“ manuell starten.

## Nutzung

1. **Einstellungen** öffnen, Anbieter/Host/Benutzer/App-Passwort setzen und **Speichern**.
2. Optional **Verbindung testen**.
3. Im Hauptfenster **Reports abrufen** — Dashboard mit Alignment-Charts, Volumen/Pass-Rate über Zeit und Aggregattabellen.
4. Alternativ **Dateien öffnen** oder XML/GZ/ZIP/EML per **Drag & Drop** laden.

### Funktionen

- **Lokaler Cache & inkrementeller Abruf:** Geparste Reports bleiben unter dem Electron-`userData`-Pfad; nur neue IMAP-UIDs werden nachgeladen.
- **Filter:** Zeitraum (7/30/90 Tage) und Domain.
- **IP-Anreicherung:** Reverse-DNS und Erkennung bekannter Absender (Google, Microsoft, Amazon SES, …).
- **Export:** CSV oder JSON der aktuell gefilterten Daten.
- **DNS-Check:** DMARC- (`p`, `rua`) und SPF-Records einer Domain abfragen.
- **Auto-Abruf:** optionales Intervall + Desktop-Benachrichtigung bei steigenden Failures.
- **Auto-Update:** prüft beim Start GitHub Releases; Download im Hintergrund, Installation nach Neustart (NSIS / AppImage / macOS ZIP).
- **Als gelesen markieren:** optional nach Abruf (`\\Seen`).

Zugangsdaten werden lokal gespeichert; das Passwort wird mit `safeStorage` verschlüsselt.

## Technik

- Electron + electron-vite + TypeScript
- IMAP: `imapflow`
- Parsing: `@koduhai/dmarc-parser` (Aggregate/RUA: XML, gzip, zip, EML)
- Updates: `electron-updater` über GitHub Releases (`latest.yml` / `latest-linux.yml` / `latest-mac.yml`)

## Hinweise

- Failure-/RUF-Reports werden nicht ausgewertet.
- Nachrichten ohne gültigen DMARC-Anhang werden übersprungen und gezählt.
- Gespeicherte Einstellungen und der Report-Cache liegen unter dem Electron-`userData`-Pfad (nicht im Repo).
- Cache leeren: Einstellungen → **Cache leeren** (nächster Abruf holt wieder alles).
- Auto-Update greift in gepackten Builds (nicht im Dev-Modus). Portable-EXE und `.deb` werden nicht automatisch aktualisiert — NSIS-Setup, AppImage und macOS-ZIP schon.
