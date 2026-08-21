# Secure upload to TAC — operator runbook

**Status:** M6 (shipped). The optional, consent-gated, outbound-only channel that
uploads an **already-encrypted** support bundle to the TAC Cloud. Everything here
is **off by default** — a fresh appliance never uploads anything.

See also: `docs/operator/support-bundles-and-diagnostics.md` (collect → approve →
export), and the design in `docs/support/SECURE-UPLOAD-ARCHITECTURE.md`.

---

## 1. What it is (and is not)

- **Outbound only.** The appliance opens the connection to TAC; the cloud can
  **never** dial in. There is no inbound listener or callback route
  (`TestNoInboundTACSurface`).
- **End-to-end encrypted to TAC.** A bundle is sealed to TAC's **public** X25519
  key *before* the HTTPS POST (NaCl sealed box). The appliance holds no matching
  private key, so it cannot decrypt what it sends — TLS is defence-in-depth, not
  the confidentiality boundary.
- **Consent-gated, per bundle, per case.** No bundle leaves the appliance without
  an explicit admin action naming a case. Enabling upload never enables telemetry,
  remote support, or bundle collection — the four consent switches are independent
  (`TestConsentSeparation`).
- **Cloud-independent.** If TAC is unreachable the appliance operates normally and
  the bundle queues (or you export it offline); nothing stalls, health stays local
  (`TestHealthWithoutCloud`).
- **No auto-upload.** There is no timer or trigger that uploads without the consent
  action (`TestNoAutoUpload`). A background worker only *delivers* bundles you have
  already consented to.

---

## 2. One-time setup

### 2a. TAC recipient trust key (encrypt-to-TAC)

The bundle is sealed to TAC's published public key. An official build **bakes** the
key in; you only configure this for a private/regional/staging TAC or an
air-gapped mirror.

- **Env (startup-scoped):**
  - `CULVERT_TAC_TRUST_KEYS` — JSON array of **public** keys that EXTEND the baked
    set: `[{"key_id":"tac-2026","alg":"x25519","public_key":"<base64>"}]`. Public
    material only — never a private key.
  - `CULVERT_TAC_ACTIVE_KEY_ID` — optional; names which trusted key new bundles
    seal to (default: the first resolved key). Use during an additive rotation.
- **Verify out-of-band.** The admin UI (**Secure Upload → TAC trust**) and
  `GET /api/support/tac-trust` show each key's `key_id`, `alg`, SHA-256
  `fingerprint`, `source` (baked/configured), and which is `active`. Confirm the
  fingerprint against TAC's published value once, over a trusted channel.
- **Rotation is additive.** Trust old + new simultaneously (overlap window); set
  `CULVERT_TAC_ACTIVE_KEY_ID` to the new key when ready. TAC keeps the retired
  private key long enough to decrypt any bundle already queued against the old key.
- **Fail-closed.** A malformed key, a low-order point, or a duplicate `key_id` with
  a different key is rejected — a bad value can only ever *remove* a sealing target,
  never widen exposure. With no trusted key, encrypt-to-TAC is unavailable and the
  consent action is refused (use offline export instead).

### 2b. Enable upload + set the origin

Default posture is `not_enabled`. In **Secure Upload → Configuration** (admin), or:

```
PUT /api/support/upload/config
{ "enabled": true,
  "origin": "https://tac.example.com",
  "credential": "<per-appliance bearer>" }     # optional; omit if TAC uses mTLS
```

- **Origin must be `https://`** and must not be a private/internal address
  (SSRF-guarded at config time *and* at dial time — a hostname that resolves to a
  private IP is refused when the upload is attempted). For air-gapped sites, leave
  upload disabled and use offline export.
- **Credential** is stored `0600`, node-local, and **never displayed** — the UI/API
  report only `credential_set: true/false`. A posture change (toggling enabled /
  origin) preserves it; send `"clear_credential": true` to remove it.
- **Node-local.** The upload config and queue are operational state: they are **not**
  exported, version-rolled-back, or synced CP→DP.

---

## 3. Upload a bundle (the consent action)

1. **Collect** a bundle and **approve** it (review the redaction report) so it is
   `READY` — see the support-bundles runbook. Only a `READY` bundle can be uploaded.
2. In the bundle's actions, choose **Upload to TAC**, enter the **case id**, and
   confirm. Or:

   ```
   POST /api/support/bundles/{id}/upload
   { "confirm": true, "case_id": "CASE-1234" }
   ```

   The request is refused (fail-closed) unless upload is enabled, a TAC trust key is
   configured, the bundle is `READY`, `confirm` is `true`, and `case_id` is present
   (and matches the bundle's bound case if it already has one). Consenting also
   **binds** the bundle to that case, so retention won't evict it mid-transfer.
3. On consent the appliance seals the bundle to TAC **once**, writes the sealed blob
   next to the bundle, and enqueues it (HTTP `202 Accepted`). A background worker
   delivers it on the appliance's own outbound schedule.

Watch progress in **Secure Upload → Queue** or:

- `GET /api/support/uploads` — the whole queue.
- `GET /api/support/bundles/{id}/upload` — one bundle's state + signed receipt.

---

## 4. Queue states & what to do

| State | Meaning | Action |
|---|---|---|
| `queued` | awaiting the next outbound attempt | none — the worker will send it |
| `uploading` | an attempt is in flight | none |
| `uploaded` | delivered; **signed receipt** stored on the entry | done — the receipt proves what was sent, when, and that the hash matched |
| `deferred` | transient failures hit the attempt cap (cloud down, timeouts) | re-arm by re-issuing the consent action, or export offline |
| `rejected` | the gateway refused it (entitlement / format / hash) | terminal; read `last_error`, fix the cause, then re-consent |

- **Transient failures** (unreachable cloud, 5xx) retry automatically with bounded
  exponential backoff and resume from the last received offset — a dropped
  connection or a restart does not restart the transfer from zero.
- **Re-arming** a `deferred`/`rejected` bundle re-seals it fresh and starts a new
  gateway session (a fresh blob is a fresh session), so a stale hash never lingers.
- The queue is bounded; completed/rejected records are retained up to a cap and
  then aged out oldest-first.

---

## 5. Offline / air-gapped

If there is no outbound path, **do not enable upload**. Instead export the encrypted
bundle and carry it on approved media to a machine with TAC portal access — the
cloud ingests it through the same pipeline. See the support-bundles runbook
§6/§6a (`--export`, passphrase or sealed-to-recipient). Local health and
`diagnose` remain fully available offline.

---

## 6. Disable / stop

- Set `enabled: false` (the origin/credential are preserved for later). The worker
  goes inert immediately — queued entries stay put and nothing is sent until you
  re-enable.
- To fully remove the destination, clear the origin and send `clear_credential: true`.

---

## 7. Where things live

| Item | Location |
|---|---|
| Upload config (enabled/origin/credential) | `<dataDir>/support/upload_config.json` (`0600`, node-local) |
| Upload queue (per-bundle state + receipt) | `<dataDir>/support/upload_queue/<bundle_id>.json` |
| Sealed-to-TAC blob (pending upload) | `<dataDir>/support/bundles/<bundle_id>/upload.csb.sealed` |
| TAC trust keys | baked into the build ∪ `CULVERT_TAC_TRUST_KEYS` (public material) |
| Active sealing key | `CULVERT_TAC_ACTIVE_KEY_ID` (else first resolved) |

**Audit trail:** the consent action is audited as `support.upload` (actor = the
admin); delivery/rejection/deferral are audited as `support.bundle.upload{,_rejected,_deferred}`
(actor = `system`). Config changes are audited as `support.upload.config`.

---

## 8. Troubleshooting

- **Consent returns 409 "upload is not enabled"** — enable it and set an origin
  (§2b).
- **Consent returns 409 "no TAC recipient trust key configured"** — the build has
  no baked key and none is configured; set `CULVERT_TAC_TRUST_KEYS` (§2a) or use
  offline export.
- **Consent returns 409 "bundle pending approval"** — approve the bundle first.
- **Consent returns 400** — missing `confirm:true`, missing/invalid `case_id`, or a
  `case_id` that disagrees with the bundle's bound case.
- **Origin refused (400)** — not `https://`, or a private/internal address.
- **Entry stuck `deferred`** — TAC was unreachable past the retry budget; check the
  origin/credential and network egress, then re-consent to re-arm, or export
  offline.
- **Entry `rejected`** — the gateway declined it; `last_error` carries a redacted
  reason (entitlement/format/hash). Resolve, then re-consent.
