# DMARC Viewer

Desktop-Tool (Electron / Node), das per **IMAP** DMARC-Aggregate-Reports aus einem Postfach holt, parst und in einer GUI anzeigt.

## Voraussetzungen

- Node.js 20+
- Für Gmail / Outlook: **App-Passwort** (nicht das normale Kontopasswort)

### App-Passwörter

- **Gmail:** Google-Konto → Sicherheit → 2-Schritt-Bestätigung → App-Passwörter. IMAP-Host: `imap.gmail.com`, Port `993`, TLS.
- **Outlook / Microsoft 365:** App-Passwort bzw. IMAP freigeben, sofern vom Tenant erlaubt. Host: `outlook.office365.com`, Port `993`, TLS.
- **Custom:** beliebiger IMAP-Server mit Benutzer/Passwort.

Native Gmail-API- / Microsoft-Graph-OAuth sind in v1 nicht enthalten — IMAP deckt die gängigen Anbieter ab.

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

GitHub Release (alle Plattformen via Actions): Tag `v1.0.0` pushen oder Workflow „Release“ manuell starten.

## Nutzung

1. **Einstellungen** öffnen, Anbieter/Host/Benutzer/App-Passwort setzen und **Speichern**.
2. Optional **Verbindung testen**.
3. Im Hauptfenster **Reports abrufen** — Dashboard mit Alignment-Charts, Volumen über Zeit und Aggregattabellen (wie bei der Kibana-Variante von parsedmarc).

Zugangsdaten werden lokal unter dem Electron-`userData`-Pfad gespeichert; das Passwort wird mit `safeStorage` verschlüsselt.

## Technik

- Electron + electron-vite + TypeScript
- IMAP: `imapflow`
- Parsing: `@koduhai/dmarc-parser` (Aggregate/RUA: XML, gzip, zip, EML)

## Hinweise

- Failure-/RUF-Reports werden nicht ausgewertet.
- Nachrichten ohne gültigen DMARC-Anhang werden übersprungen und gezählt.
- Gespeicherte Einstellungen liegen unter dem Electron-`userData`-Pfad (nicht im Repo).
