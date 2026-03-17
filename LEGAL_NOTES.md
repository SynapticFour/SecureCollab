# SPDX-License-Identifier: Apache-2.0

## LEGAL NOTES (Internal Draft, Non-Binding)

This document is an internal guideline for how we talk about security, privacy, and compliance in the SecureCollab repository (code comments, UI text, documentation).

It is **not** legal advice and does **not** replace consultation with qualified counsel.

---

## 1. General Principles

- **No legal promises in technical docs**
  - Documentation, comments, and UI text should describe **what the code does** and which **security properties it aims for**, but must **not** be phrased as:
    - legally binding guarantees,
    - compliance confirmations, or
    - contractual commitments.

- **Separate “what we do” from “what this means legally”**
  - We may describe:
    - implemented cryptographic mechanisms,
    - architecture decisions,
    - OWASP-motivated controls,
    - known limitations.
  - We do **not** derive or state legal conclusions such as “DSGVO-konform”, “HIPAA-compliant”, or “sufficient for regulatory approval”.

- **Assumptions must be explicit**
  - When we describe security properties, we always assume:
    - correct implementation,
    - correct deployment and configuration,
    - honest use of SDKs by institutions.
  - If a statement depends on these, say so explicitly (e.g. “under the stated cryptographic model and assuming correct implementation…”).

---

## 2. Phrases to Avoid vs. Preferred Alternatives

### 2.1 Guarantees and absolutes

- **Avoid** (in all languages):
  - “garantiert”, “Garantie”, “KRYPTOGARANTIE”
  - “Guarantee(s)”
  - “100% sicher”, “vollständig sicher”, “absolut sicher”
  - “mathematisch ausgeschlossen”, “mathematisch unmöglich”

- **Preferred patterns**:
  - “Ziel des Designs ist …”
  - “das Protokoll ist so ausgelegt, dass …”
  - “unter dem gewählten kryptographischen Modell und bei korrekter Implementierung ist es nach heutigem Stand der Technik praktisch nicht möglich, dass …”
  - “kryptographische Einordnung (kein Rechtsversprechen): …”
  - “Aussage über das Protokolldesign (kein Rechtsversprechen): …”

### 2.2 Compliance and regulation

- **Avoid**:
  - “DSGVO-konform”, “DSGVO compliant”
  - “HIPAA compliant”
  - “compliant with …” (without a completed audit and explicit legal sign-off)

- **Preferred patterns**:
  - “ausgelegt auf Szenarien mit DSGVO/HIPAA-Anforderungen”
  - “Vorbereitung auf DSGVO/HIPAA-Anforderungen (formale Compliance hängt von Deployment, Verträgen und Prozessen ab)”
  - “geplant: Abschluss eines DSGVO-konformen Auftragsverarbeitungsvertrags (DPA), HIPAA BAA etc., abhängig von konkreten Kundenprojekten”
  - Always add a qualifier: this is a **goal or direction**, not a current certification.

### 2.3 Evidence and “proof”

- **Avoid**, unless very precisely scoped:
  - “beweist”, “beweist, dass …” (as a legal conclusion)
  - “proves that …” (as a legal conclusion)

- **Preferred patterns**:
  - “liefert kryptographische Indikatoren dafür, dass …”
  - “ermöglicht es, nachzuprüfen, ob …”
  - “nach heutigem Verständnis der zugrunde liegenden Kryptographie spricht der Hash-Verlauf dafür, dass …”

---

## 3. Disclaimers and Status

### 3.1 Project status

- Always make clear:
  - The project is currently a **hobby / proof-of-concept**.
  - It has **no external security audit** and **no legal review** yet.
  - It is **not production-ready for real patient data**.

### 3.2 No legal advice

- When we talk about verification, integrity, or compliance in docs:
  - Add a clear statement that:
    - the documentation is **not legal advice**,
    - institutions must obtain their **own legal and compliance assessment** for their use case.

Example (English):

> “This documentation describes the intended security properties of the software. It does not constitute legal advice or a formal compliance assessment. Institutions should consult their own legal and compliance experts for their specific deployment.”

Example (German):

> “Diese Dokumentation beschreibt die beabsichtigten Sicherheitseigenschaften der Software. Sie stellt keine Rechtsberatung und keine formale Compliance-Bewertung dar. Institutionen sollten für ihren konkreten Einsatzfall eigene rechtliche und Compliance-Prüfungen durchführen.”

---

## 4. OWASP and Security Documentation

- We **can**:
  - refer factually to OWASP categories,
  - describe which mitigations are implemented,
  - list known open issues and limitations.

- We **must not**:
  - claim “vollständig OWASP-konform” oder ähnliches.
  - present OWASP mappings as a guarantee of security or compliance.

Preferred wording:

- “orientiert sich an OWASP Top 10”
- “die folgenden Maßnahmen wurden mit Blick auf OWASP A0X umgesetzt”
- “diese Aufstellung ist eine technische Einschätzung, keine formale Zertifizierung”

---

## 5. Code Comments and UI Text

- **Code comments**:
  - Should explain **intent, assumptions and trade-offs**, not make legal statements.
  - If a comment talks about “Guarantees”, rephrase to “intended properties” and, where helpful, refer to this file.

- **UI text (Frontend)**:
  - Focus on:
    - what users can do,
    - which cryptographic mechanisms are used,
    - which steps are required for a workflow.
  - Do **not**:
    - claim that a study is “conducted under cryptographic guarantees”,
    - suggest that use of the app by itself makes a study compliant with any regulation.

---

## 6. When in Doubt

- If you are about to write something like “konform”, “garantiert”, “beweist”, or to name a specific regulation:
  1. Prefer a **technical description** of the mechanism.
  2. Make assumptions explicit (“unter der Annahme, dass …”).
  3. Add a short disclaimer that this is **not legal advice**.

- For any planned marketing/external copy (website, pitch decks), run the text separately through:
  - product,
  - legal/compliance,
  - and security review.

