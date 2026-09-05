# ADR-0031: Support export/upload consent & trust model; remote support deferred

- **Status:** Accepted — partially implemented. Encrypted/sealed export shipped in appliance track M4, and the secure-upload queue (M6) has since shipped too (see `docs/support/SUPPORTABILITY-ROADMAP.md`); remote support beyond upload remains deferred as this ADR describes. This ADR's explicit TLS 1.3 requirement is not yet enforced in code — `internal/supportupload/upload.go`'s `http.Transport` sets no `TLSClientConfig`/`MinVersion`, so it accepts Go's default minimum rather than requiring TLS 1.3.
- **Date:** 2026-07-12
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (ratified through shipped implementation)
- **Relates to:** ADR-0028 (bundle framework), ADR-0029 (redaction), `internal/backupcrypt`, `internal/ssrf`, the release-catalog trust/origin model. Full design in `docs/support/SECURE-UPLOAD-ARCHITECTURE.md`.

## Context

A support bundle must be deliverable to TAC both **offline** (air-gapped) and, later, **online**, without ever creating a cloud dependency for local diagnostics, without silent background egress, and without conflating support consent with telemetry consent. The audit found reusable crypto (`backupcrypt`: AES-256-GCM, PBKDF2 600k, AAD-bound) but **no recipient/public-key model** (the usual pattern for encrypting a bundle to a vendor) and **no upload/remote path**. It also found a clean precedent for an external, trust-pinned, SSRF-guarded, operator-overridable origin: the release catalog.

Remote interactive support is the single highest-risk capability a no-shell appliance could add.

## Decision

1. **Offline export is the default and always available** (M4), works air-gapped and in recovery mode. Optional encryption in two modes: **passphrase** (`backupcrypt`, verifiable by `culvert support validate`) and **recipient public key** (age/X25519 to TAC's pinned public key) so only TAC decrypts and no shared secret is needed. Recipient trust keys are public material, baked+overridable like the catalog roots.
2. **Online upload is opt-in, explicit, per-bundle** (M6): admin-gated, `case_id`-bound, TLS 1.3 + inline SSRF guard (`isPrivateHost` at the call site + `SafeDialContext`), recipient-key E2E encrypted independent of TLS, resumable, tenant-scoped credential, signed receipt with server-side hash validation. **No code path uploads automatically.** A scheduled/background upload would require a separate ADR and its own switch.
3. **Consent is four independent switches** — bundle collection, upload, remote support, telemetry — each with its own default and audit trail. Enabling one never enables another (P6). Telemetry (M7) is a strict subset of bundle-eligible aggregate metrics, separately consented.
4. **Remote support is deferred, interface-only.** Recommendation: **do not build it for the current stage** — offline/online bundle exchange plus targeted diagnostics cover the workflow, and a remote session (however bounded) is the highest-risk addition to a no-shell appliance. The CLI/API reserve `support remote {approve|status|revoke}` returning `not_enabled`. If ever built, it MUST be per-session-approved, time-bound with an auto-revoke watchdog, per-command allowlisted (same `DiagCommand` registry — **never a shell**), mutually authenticated, fully recorded, instantly revocable, and tenant-isolated — behind its own ADR + threat model.
5. **Local diagnostics never depend on the cloud** (P10): all collection, redaction, and encryption are in-binary; the upload origin is optional and, like the catalog, has a trust-safe opt-out.

## Consequences

**Positive**
- A future cloud TAC portal is a **flag flip**, not an appliance redesign — the appliance side is a generic "encrypt-to-recipient + authenticated resumable POST + receipt" client reusing the catalog-origin trust pattern.
- The recipient-key model closes the audit's "no asymmetric TAC encryption" gap and is the safer default than a shared passphrase.
- Four separate consent switches make "support ≠ telemetry" auditable and testable (`TestConsentSeparation`).
- Deferring remote support keeps the appliance's no-shell guarantee intact while leaving a safe, pre-shaped seam.

**Negative / cost**
- Recipient encryption adds an X25519/age dependency and a pinned-key lifecycle (rotation, override) to maintain.
- Upload adds a network egress surface; contained by opt-in + SSRF guard + tenant scoping + E2E encryption + no-auto-upload test.

**Neutral**
- Upload ships disabled (`not_enabled`) until configured; offline is unaffected.

## Alternatives considered

1. **Passphrase-only encryption.** Rejected as the *only* mode: requires an out-of-band shared secret and offers no recipient guarantee. Kept as an option for operator-controlled offline transfer.
2. **Automatic/background upload of bundles.** Rejected: violates "nothing uploads automatically"; a silent egress channel is unacceptable on a security appliance. Any future scheduled upload needs its own ADR + consent.
3. **Build remote support now.** Rejected for the current stage (see §4); designed as a deferred, tightly-bounded seam instead.
4. **Reuse telemetry consent for support upload.** Rejected: conflates two very different data flows; four independent switches is the invariant.
