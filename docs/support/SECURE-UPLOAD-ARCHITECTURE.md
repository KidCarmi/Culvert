# Culvert Support — Secure Export, Upload & Remote-Support Architecture

- **Status:** Proposed (design). Offline export is M4; online upload is M6; remote support is a deferred, interface-only design (§4).
- **Depends on:** `SUPPORT-BUNDLE-SPEC.md`, `REDACTION-MODEL.md`, `internal/backupcrypt`, `internal/ssrf`.
- **Absolute rules:** nothing uploads automatically (P4); local diagnostics never depend on the cloud (P10); telemetry consent is separate from support consent (P6).

---

## 1. Two workflows, one bundle

A CSB is produced identically regardless of transport. Export is a *terminal* lifecycle step (`READY → EXPORTED | UPLOADED`), always operator-initiated, always after the mandatory redaction preview.

```
CSB (READY) ──┬── OFFLINE: download (optionally encrypted) → manual transfer → TAC
              └── ONLINE : explicit, audited, resumable upload → TAC portal (M6)
```

---

## 2. Offline export (M4 — the default, always available)

The offline path must work air-gapped and with the GUI down (recovery CLI).

- **Download:** `GET /api/support/bundles/{id}/download` (admin) streams the `.csb.tgz`; the CLI `culvert support collect` writes it to a path. No network egress from the appliance.
- **Encryption (optional but recommended for sensitive bundles):** two modes, both reusing audited primitives:
  1. **Passphrase** — `internal/backupcrypt` (AES-256-GCM, PBKDF2-SHA256 600k iters, AAD-bound header, opaque error). Operator supplies a passphrase; TAC receives it out-of-band. Same envelope as backups, so `culvert support validate` verifies it.
  2. **Recipient public key (age-style)** — encrypt-to-TAC's published age/X25519 public key so **only** TAC's private key decrypts, and the operator needs no shared secret. This is the missing "recipient model" the audit flagged; it is the correct default for vendor upload. The TAC public key(s) are baked/pinned like the release-catalog trust roots (public material only) and overridable for private/regional TAC.
- **Integrity verification:** the recipient runs `culvert support validate` (or an offline verifier) to check `bundle_sha256` + per-section hashes + (if encrypted) the AEAD tag before opening. A tampered or truncated bundle fails closed.
- **Manual transfer:** the operator moves the file by whatever channel policy allows (portal upload, secure file share, physical media for air-gap). The appliance is not involved.

Encryption choice is recorded in the manifest (`encrypted: none|passphrase|recipient`, plus recipient key id) so provenance is clear.

---

## 3. Online upload (M6 — opt-in, explicit, never silent)

Architected now so a future cloud TAC portal is a flag flip, not a redesign. **Not enabled in MVP.**

### 3.1 Contract
- **Explicit opt-in per upload.** `POST /api/support/uploads {bundle_id, case_id}` (admin). There is no setting that makes uploads automatic or background; each upload is one audited action (`support.upload`).
- **Case binding.** An upload requires a `case_id`; the portal validates it. The bundle's manifest already carries `case_id`.
- **Secure, authenticated transport.** TLS 1.3 to the portal; the appliance authenticates with a per-appliance credential (enrollment-style, rotatable). **Inline SSRF guard** (`url.Parse` + scheme + `isPrivateHost` at the call site, per CLAUDE.md) + `internal/ssrf.SafeDialContext` so the upload endpoint cannot be pointed at internal infra; private-IP origins rejected (mirrors the release-catalog SSRF posture).
- **Encryption in transit and at rest.** The uploaded bundle is the **recipient-key-encrypted** artifact (§2), so it is end-to-end encrypted to TAC independent of TLS; the portal stores it encrypted-at-rest.
- **Resumable.** Chunked/resumable upload (offset-based) so a large bundle survives a flaky link; the appliance retries with bounded exponential backoff and never blocks the proxy hot path (background op with a cancel).
- **Tenant isolation.** The per-appliance credential scopes uploads to that customer's tenant; the portal enforces tenant boundaries; a bundle can never land in another tenant's case.
- **Expiration & retention.** Uploaded bundles expire per portal policy; the appliance keeps only the local copy under its own retention (§SUPPORT-BUNDLE-SPEC §6). The upload does not extend local retention.
- **Upload receipt.** On success the portal returns a signed receipt `{case_id, bundle_id, bundle_sha256, received_at}` which the appliance stores in the bundle history and audit — proof of what was sent, when, and that the hash matched (server-side validation of the hash before acceptance).
- **Server-side validation.** The portal re-verifies format, size bounds, hash, and that the bundle decrypts to a valid manifest before accepting — rejecting malformed/oversized/tampered uploads (defense against a malicious appliance and against corruption).
- **No silent background data transfer.** A scheduled/automatic upload capability is explicitly out of scope; if ever added it would require a separate ADR and a distinct, separately-consented switch.

### 3.2 Why this generalizes to a cloud TAC portal
The appliance side is a thin, generic "encrypt-to-recipient + authenticated resumable POST + receipt" client. The portal is an external service the appliance knows only by URL + trust root + tenant credential — exactly the shape of the existing release-catalog origin (baked default, operator-overridable, SSRF-guarded, trust-pinned). Adding the portal later reuses that whole pattern; no appliance framework change.

---

## 4. Remote support (deferred — interface only, recommendation: NOT for current stage)

**Recommendation: do not build remote interactive support in MVP.** Rationale: the appliance's entire value proposition is that the customer does not expose OS/shell access; a remote-session capability, however bounded, is the single highest-risk addition and is not needed while offline/online bundle exchange covers the diagnostic workflow. Most TAC cycles resolve from a good bundle + targeted diagnostics + a follow-up bundle at a raised debug level.

**But design the seams so it can be added safely.** If/when justified, remote support must be:
- **Explicit customer approval, per session** — an admin approves a specific, time-bound session; no standing access.
- **Time-bound** — a hard TTL (like debug levels, P9) with an auto-revoke watchdog; the session cannot outlive its window.
- **Per-command authorized** — every action is a `DiagCommand` from the fixed registry (DIAGNOSTIC-COMMAND-FRAMEWORK §5); **no general shell, ever**; the remote party can only invoke the same allowlisted, audited, typed diagnostic verbs an operator can.
- **Mutually authenticated** — TAC engineer identity + appliance identity, both cert-pinned; no shared password.
- **Fully recorded** — every command + output logged to an immutable session record (redacted), surfaced in the timeline (`category: support`) and downloadable by the customer.
- **Immediately revocable** — the admin can kill the session instantly; revoke is fail-closed (loss of the control channel ends the session).
- **Strong tenant isolation** — a session is scoped to one appliance/tenant; no lateral reach.
- **Clearly separated from telemetry** — remote support is not telemetry and shares no consent, credential, or channel with it (P6).

The command framework already reserves `culvert support remote {approve|status|revoke}` returning `not_enabled`, so the CLI/API shape is stable. Implementation would need a dedicated ADR and threat model.

---

## 5. Consent model (support ≠ telemetry, P6)

| Switch | Governs | Default | Consent granularity | Audit action |
|---|---|---|---|---|
| Support bundle collection | producing a local CSB | available (RBAC-gated) | per-bundle | `support.bundle.*` |
| Support upload | sending a CSB to TAC | **off** | per-upload, per-case | `support.upload` |
| Remote support | interactive TAC session | **off/not-enabled** | per-session, time-bound | `support.remote.*` |
| Telemetry (M7) | continuous opt-in metrics phone-home | **off** | global opt-in, separate | `telemetry.*` |

These are four independent switches with four audit trails. Enabling one never implies another. Telemetry (M7) reuses the transport pattern but is a **strict subset** of bundle-eligible metrics (HEALTH-AND-EVENT §7), separately consented, and never carries bundle contents.

---

## 6. Test surface

| Test | Asserts |
|---|---|
| `TestNoAutoUpload` | no code path uploads without an explicit per-bundle admin action |
| `TestOfflineBundleAirGapped` | download + validate works with no network (P10) |
| `TestRecipientEncryptOnlyTACDecrypts` | recipient-mode bundle decrypts only with the TAC key |
| `TestUploadSSRFGuarded` | upload origin rejects private-IP/internal targets |
| `TestUploadRequiresCaseAndAdmin` | upload without case_id or below admin is refused |
| `TestUploadReceiptHashMatch` | receipt hash equals bundle hash; mismatch rejected |
| `TestRemoteSupportNotEnabled` | remote verbs return `not_enabled` in MVP |
| `TestConsentSeparation` | enabling support never enables telemetry/upload/remote |
