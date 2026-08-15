# Engineering Decisions (ADR-lite)

Track important architectural and operational decisions here.

## Template

### YYYY-MM-DD - Decision title

- **Context:** Why this decision was needed.
- **Decision:** What was chosen.
- **Consequences:** Trade-offs, risks, and follow-up actions.

### 2026-08-15 - Replace header identity with signed tokens

- **Context:** Due diligence: `X-User-Email` was spoofable identity; release shares accepted arbitrary strings; UI claimed threshold decrypt.
- **Decision:** Password accounts + HMAC Bearer tokens. Join requires invite_code. Release share is SHA3(job_id|email|key_commitment). UI/docs aligned to creator-key + authorization shares.
- **Consequences:** Demo still has unverified email. Production must set SECRET_KEY and should disable open registration. SSO remains Phase 2.

- **Context:** Repositories had uneven governance and CI security posture.
- **Decision:** Standardize governance docs, quality gates, and security scanning workflows.
- **Consequences:** Better consistency and contributor trust; ongoing maintenance required to keep checks aligned with stack changes.
