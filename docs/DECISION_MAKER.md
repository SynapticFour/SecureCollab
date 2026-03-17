# SPDX-License-Identifier: Apache-2.0

## SecureCollab – Kurzinfo für Entscheider:innen

**Zielgruppe:** Klinikleitungen, Studienzentren, Datenschutz-/Compliance-Verantwortliche, IT-Sicherheitsbeauftragte.

**Status:** Hobby-/Proof-of-Concept-Projekt. Kein Medizinprodukt, keine Zertifizierung, kein externer Security Audit, keine Rechtsberatung.

Diese Seite soll helfen zu verstehen, **was SecureCollab technisch macht** und **was ausdrücklich nicht zugesagt wird**. Sie ersetzt keine individuelle rechtliche oder regulatorische Bewertung.

---

## 1. Technische Kurzbeschreibung (vereinfacht)

- Mehrere Institutionen können verschlüsselte Datensätze (z. B. klinische Tabellen) beitragen.
- Die Plattform führt statistische Auswertungen auf **verschlüsselten** Daten aus (Homomorphic Encryption, CKKS).
- Jede Institution behält ihren **Key Share** lokal; der Server kennt nur einen Public Key.
- Es gibt:
  - einen hash-verketteten Audit-Trail,
  - kryptographische Commitments pro Upload,
  - einen Codebase-Hash zur Verifikation der eingesetzten Version.

Details: siehe `DOCUMENTATION.md`, `SECURITY.md`, `docs/CRYPTOGRAPHY.md`. Für eine technische Anleitung zum Start eines Piloten oder einer Demo: `docs/DEPLOYMENT.md` (Abschnitt „How to run a pilot“).

---

## 2. Was **nicht** zugesagt wird

Für einen produktiven Einsatz – insbesondere mit echten Patientendaten – sind folgende Punkte **nicht** gegeben:

- **Keine formale Compliance-Aussage**
  - Es wird **nicht** zugesagt, dass SecureCollab „DSGVO-konform“, „HIPAA-compliant“ oder für einen bestimmten Rechtsraum „ausreichend“ ist.
  - Ob ein konkretes Deployment rechtlich zulässig ist, hängt von:
    - der jeweiligen Rechtsordnung,
    - Verträgen (z. B. AV-Vertrag/DPA),
    - internen Prozessen (Zugriffssteuerung, TOMs, Löschkonzepte),
    - und der tatsächlichen Nutzung ab.

- **Keine Zertifizierung oder externe Prüfung**
  - Kein ISO 27001, keine BSI-Zertifizierung, keine Medizinprodukte-Zulassung (MDR/FDA), kein externer Penetrationstest abgeschlossen.
  - Roadmap-Dokumente beschreiben **geplante** Maßnahmen (z. B. Audit, TEE), aber keine bereits erreichte Zertifizierung.

- **Keine Garantie für Eignung in konkreten Verfahren**
  - Es wird nicht zugesagt, dass der Einsatz von SecureCollab:
    - eine Ethikkommission, Data Access Committee oder Aufsichtsbehörde überzeugt,
    - Anforderungen einer konkreten Studie oder eines Fördergebers erfüllt.

- **Keine Zusage zur Verfügbarkeit oder Datenaufbewahrung**
  - Es gibt keine SLA, keine Hochverfügbarkeits- oder Backup-Garantie.
  - Verantwortlich für Betrieb, Backups und Disaster Recovery ist jeweils die Institution, die eine Instanz betreibt.

---

## 3. Was technisch angestrebt wird (ohne Rechtsversprechen)

Die Dokumentation beschreibt u. a. folgende **Designziele** (keine rechtliche Garantie):

- Server führt Berechnungen auf verschlüsselten Daten aus und speichert nur Ciphertexte.
- Private Key Shares bleiben bei den Institutionen; der Server kennt nur den Public Key.
- Audit-Trail und Commitments sollen Manipulationen **technisch erkennbar** machen.
- Konfiguration und Deployment sollen sich an OWASP-Empfehlungen orientieren (Rate Limiting, Input-Validierung, Security-Header, Dependency-Scanning etc.).

Im Zweifel gelten die jeweils aktuellen Texte in `SECURITY.md`, `docs/OWASP_ANALYSIS.md` und `LEGAL_NOTES.md`.

---

## 4. Was Institutionen vor einem Einsatz tun sollten

Wenn der Einsatz in einer realen Studie oder Produktion diskutiert wird, sollten mindestens folgende Schritte erfolgen:

1. **Rechtliche Bewertung**
   - Prüfung durch die eigene Rechtsabteilung oder externe Kanzlei:
     - Rollenmodell (Verantwortlicher/Auftragsverarbeiter),
     - Notwendigkeit und Inhalt eines AV-Vertrags (DPA),
     - ggf. HIPAA/BAA, DSGVO Art. 28, Art. 32, nationale Spezialvorschriften.

2. **Datenschutz / Informationssicherheit**
   - Datenschutz-Folgenabschätzung (DPIA), falls erforderlich.
   - Bewertung der technischen und organisatorischen Maßnahmen (TOMs) des konkreten Deployments:
     - Schlüsselmanagement,
     - Zugriffsberechtigungen,
     - Logging & Monitoring,
     - Backup- und Löschkonzepte.

3. **Security-Review**
   - Unabhängige technische Prüfung des konkreten Deployments:
     - Konfiguration (TLS, Secrets, Firewalls),
     - Penetrationstest / Red Teaming,
     - Überprüfung der HE-Parameter (sofern relevant).

4. **Vertragliche Einbettung**
   - Klare Vereinbarungen zu:
     - Verantwortlichkeiten (Betrieb, Incident Response),
     - Support und Wartung,
     - Datenhoheit und Exit-Szenarien (Export/Löschung).

---

## 5. Wichtig: Diese Doku ist keine Rechtsberatung

Weder dieses Dokument noch andere Dateien im Repository (README, DOCUMENTATION, SECURITY, OWASP-Analyse usw.) stellen Rechtsberatung dar. Sie beschreiben den technischen Stand und die beabsichtigten Eigenschaften der Software.

Ob eine konkrete Nutzung rechtlich zulässig ist, muss immer im Einzelfall von qualifizierten Jurist:innen und Compliance-Verantwortlichen beurteilt werden.

