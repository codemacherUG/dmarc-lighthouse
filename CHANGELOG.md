# Changelog

## Unreleased — changes since v1.0.41

### English

- Added source assessment details with message-count summaries for DMARC pass/fail, receiver disposition, and SPF/DKIM outcomes.
- Expanded failure diagnosis with explicit likely-legitimate, possibly-legitimate, forwarded, and suspicious verdicts, raw authentication evidence, alignment, and actionable recommendations.
- Added persistent per-domain DKIM selector preferences. Report-discovered selectors are incorporated without re-enabling selectors that were disabled, and both the domain health check and manual DNS check honor the enabled selectors.
- Added per-domain sending-service management beside DKIM settings. Services can be added and edited inline in an accordion; the add form remains available while editing.
- Removed the duplicate sending-service editor from global Settings. Source-review actions now open the relevant domain settings when a domain can be identified.
- Made the domain-health tiles wrap responsively while using available space on wider screens.

### Deutsch

- Details zur Quellenbewertung fassen DMARC-Pass/Fail, Empfänger-Disposition und SPF-/DKIM-Ergebnisse mit Nachrichtenanzahl zusammen.
- Die Fehlerdiagnose unterscheidet jetzt explizit zwischen wahrscheinlich legitim, möglicherweise legitim, weitergeleitet und verdächtig. Sie zeigt Authentifizierungsnachweise, Alignment und konkrete Empfehlungen.
- DKIM-Selectoren lassen sich pro Domain dauerhaft verwalten. In Reports neu entdeckte Selector-Einträge werden ergänzt, ohne zuvor deaktivierte Selectoren wieder zu aktivieren. Domain-Ampel und manueller DNS-Check berücksichtigen die aktivierten Selector-Einstellungen.
- Sende-Dienste lassen sich zusammen mit den DKIM-Einstellungen pro Domain verwalten. Hinzufügen und Bearbeiten sind integriert; die Bearbeitung klappt als Accordion direkt im Eintrag auf und lässt das Formular zum Hinzufügen sichtbar.
- Der doppelte Sende-Dienst-Editor wurde aus den globalen Einstellungen entfernt. Aktionen zur Prüfung neuer Quellen öffnen jetzt die passende Domain-Verwaltung, sofern die Domain ermittelt werden kann.
- Die Domain-Ampel-Karten umbrechen responsiv und nutzen auf breiten Ansichten den verfügbaren Platz.
