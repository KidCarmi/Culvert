# Support bundles & diagnostics — operator runbook

How to collect redacted diagnostics for a support case, run on-appliance
diagnostics, verify bundle integrity, and hand an encrypted bundle to TAC. All of
this is reachable from the **Support** panel in the admin UI and from the
`/api/support/*` and `/api/diagnose/*` admin API.

Everything here is **redacted at source**: secrets are dropped and identifiers are
masked before anything is written to disk. A "standard" bundle may contain
*internal* (non-secret) operational detail — never credentials — so bundle
creation and download are role-gated.

- **Roles:** viewer (read status/health/reports/validate), operator (collect,
  diagnose, download, delete), admin (create bundles, set capture level, approve).
- **Nothing leaves the appliance without approval:** a freshly created bundle is
  **pending** until an admin reviews its redaction report and approves it. Only a
  **ready** bundle can be downloaded — plain or encrypted.

---

## 1. Collect a bundle

**UI:** Support panel → pick a **Scope** and **Level**, optionally a **case id**,
then **Create bundle**.

**API:** `POST /api/support/bundles?scope=<scope>&level=<0..4>&case=<id>` (admin).

- **Scope** — `standard` collects everything; an incident scope
  (`tls`, `upstream`, `policy`, `storage`, `dns`, `cluster`, `scan`) collects only
  the collectors relevant to that incident plus the always-on baseline
  (product, health, readiness, diagnostics, crash, timeline, runtime). Out-of-scope
  collectors are recorded as skipped with a `scope=<name>` note.
- **Level** — capture depth. `L1` is the standard bundle; `L2` adds the runtime/host
  snapshot; higher levels are reserved. Leave the UI level on **Auto** to use the
  effective *capture-level controller* setting (see §2); an explicit level overrides
  it for that one bundle.
- **case id** — optional, binds the bundle to a support case for triage/history
  (letters/digits/`._-`, ≤64, no whitespace).

The bundle is written under `<dataDir>/support/bundles/<id>/`. Three retention
bounds keep the bundle store from growing without limit (all audited as
`support.bundle.expire`, and surfaced read-only on `/api/support/status`):

- **Count cap** — only the newest *N* evictable bundles are kept (default 10); the
  oldest are evicted when a new bundle is built. **Configurable** (`keep`, 1–10000).
- **Age cap** — a background janitor evicts any evictable bundle older than the max
  age (default 30 days), so an **idle** appliance (one that has stopped creating
  bundles, and so never triggers the count cap) still ages out stale bundles.
  A bundle whose timestamp can't be read is kept (fail-safe). **Configurable**
  (`max_age_days`, 1–3650).
- **Size cap** — a hard ceiling on the total store size (default 2 GiB); the oldest
  evictable bundles are reclaimed above it. Without this, a store of large bundles
  could wedge bundle creation — the free-disk preflight only *refuses* a new build,
  it never reclaims. **Always active** (not configurable — the disk-safety backstop).

### Tuning the count and age caps

The **Retention tuning** card in the Support panel (admin-only), or
`GET`/`PUT /api/support/retention`, sets the `keep` and `max_age_days` caps.

- The caps are **node-local**: each node stores its own, durable in
  `admin_settings.json`. They are deliberately **off** config export/import,
  version-rollback, and CP→DP cluster sync — a rollback or a fleet push must never
  mass-evict forensic evidence. In a cluster, set them per node; each node's
  effective caps are visible on its own `/api/support/status`.
- A `PUT` is a **partial** patch: send only the field you want to change; an omitted
  field is left unchanged (so setting `keep` can never silently reset `max_age_days`).
  Out-of-range values are **rejected**, not clamped. Disabling a cap is not supported
  — the size cap is the always-on backstop.
- Tightening a cap is a **one-way door**. If the new caps would evict any
  non-evidence bundle, the `PUT` returns `409` with an `evict_count`; the UI asks you
  to confirm, and the API requires a matching `confirm_evict` to proceed. Case-bound
  (evidence) bundles are never counted; **pending bundles are exempt from the count
  cap only** — a tightened *age* cap can still age out (and therefore count) a stale
  unapproved pending bundle. The tightened caps take effect on the **next janitor
  sweep** (within the sweep cadence), not instantly — so a mistaken tighten can be
  re-widened before the sweep runs. `GET` reports `pending_evictions`: how many
  bundles the *current* caps will remove on the next sweep.
- A hand-edited out-of-range persisted value (e.g. `keep: 0`) is **refused on load**
  and the compiled defaults are kept — a corrupt file can never wipe the store.

**Evidence is never auto-deleted.** A bundle bound to a support **case** (a
`case=<id>` on creation) is exempt from *all three* caps — it is forensic evidence
for an open case, so retention will never delete it. A bundle still awaiting
approval (**pending**) is additionally exempt from the count cap, so building a
fresh bundle can never evict one an admin is mid-review on. (Consequence: if the
store fills entirely with case-bound bundles, retention cannot reclaim space —
unbind or delete them manually.) Retention is **one-way**: a deleted bundle is
gone; nothing restores it.

If a bundle you expected is missing, `/api/support/status` (and the Support panel
header) shows retention observability: how many bundles have been evicted since
boot (`retention_evicted_total`) and when the age janitor last ran
(`retention_last_sweep`) — so an eviction is never silent. The same counters are
scrapable on `/metrics` for durable alerting:
`culvert_support_bundle_retention_evicted_total` (counter) and
`culvert_support_bundle_retention_last_sweep_timestamp_seconds` (gauge — alert if
it goes stale relative to the sweep cadence).

---

## 2. Capture-level controller (deeper capture, bounded)

When you need a deeper bundle while reproducing an incident, elevate the **default**
capture level for a bounded window instead of leaving verbose capture on.

**UI:** Support panel → **Capture level** card → pick a level + TTL (minutes) →
**Set level**. **Revert now** drops it early (operator).

**API:** `GET/POST/DELETE /api/support/debug-level`.

- **A TTL is mandatory** — an elevation can never be open-ended (bounded 1 min … 24 h).
- **Auto-revert survives a restart:** the effective level is computed from the
  persisted expiry, so a crash/restart mid-window still reverts to baseline the
  moment the wall clock passes the expiry. A background watchdog also reverts it
  actively and audits the change.
- Any bundle created with **Auto** level while an elevation is in force captures at
  the elevated level; after expiry it silently returns to baseline `L1`.

---

## 3. Approve → download

1. **Review** the redaction report: Support panel → **Report** (or
   `GET /api/support/bundles/{id}/redaction-report`, viewer). It is counts-only —
   how much was masked/dropped/scrubbed per section and each section's max data
   class — never any values.
2. **Approve:** admin → **Approve** (or `POST /api/support/bundles/{id}/approve`).
   The bundle flips to **ready**.
3. **Download:** operator → **Download** (`GET /api/support/bundles/{id}`) for the
   plain `.csb.tgz`, or **Encrypt** for a passphrase-encrypted copy (see §6).

---

## 4. Verify integrity (tamper detection)

Before or after transport, confirm a bundle is intact.

**UI:** Support panel → **Validate** on a bundle row.
**API:** `GET /api/support/bundles/{id}/validate` (viewer).

It re-derives every collected section's SHA-256 from the bundle's own bytes and
compares to the manifest, re-derives the manifest self-hash, and rejects duplicate
archive entries. A mismatched or missing section, an edited manifest, or a swapped
manifest all report **not ok**. The verdict is integrity metadata only (section ids
+ booleans) — it never exposes section content.

---

## 4b. Inspect a bundle without downloading

See a bundle's section inventory, sizes, data classes, collection outcome, and
integrity anchor before deciding to download or approve it.

**UI:** Support panel → **Manifest** on a bundle row.
**API:** `GET /api/support/bundles/{id}/manifest` (viewer).

It returns the bundle's manifest metadata verbatim — secret-free by construction
(section ids/paths/sizes/classes/status + `manifest_sha256`/`bundle_sha256`
integrity hashes, never any values). Complements the counts-only redaction report
(§3) and the hash-recompute `validate` (§4) with "what does this bundle contain,
and how big is it" — no tarball download required.

---

## 4a. Export (exfiltration) history

Every way a bundle leaves the appliance — plain download, passphrase-encrypted,
or sealed — is audited. Review who took a given bundle off the box and how.

**UI:** Support panel → **Exports** on a bundle row.
**API:** `GET /api/support/bundles/{id}/exports` (viewer).

It returns the recent export events (actor, time, form) for that bundle — read-only
audit metadata, never bundle content. History comes from the in-memory audit ring,
so it is **recent-only** (oldest events are evicted); the durable audit trail /
SIEM stream remains the system of record.

---

## 5. Case workflow

- **Bind** a bundle to a case at creation (§1).
- **Find** every bundle for a case: Support panel → **filter by case**, or
  `GET /api/support/bundles?case=<id>` (viewer). A malformed filter is rejected;
  an absent/empty one lists everything.

---

## 6. Encrypted export for TAC

Hand a redacted bundle to TAC over an untrusted channel without sharing a stored key.

**UI:** Support panel → **Encrypt** on a ready bundle → enter a passphrase → the
`.csb.enc` downloads.
**API:** `POST /api/support/bundles/{id}/download-encrypted` (operator, body
`{"passphrase":"…"}`).

- The bundle is wrapped in the appliance's tamper-evident backup/export envelope
  (`CVRTBK01`: PBKDF2-SHA256 → AES-256-GCM, random salt + nonce, the fixed header
  bound to the ciphertext via AAD so any header tampering — including a KDF
  iteration-count downgrade — fails authentication). This is the same envelope the
  backup/restore path uses, so a TAC/CLI validator recognises it
  (`backupcrypt.IsEncryptedBlob`).
- The passphrase is used once to derive the key and is **never logged, persisted,
  or echoed**. Choose 12–512 characters and share it with TAC out-of-band.
- Encryption is still an exfiltration, so it obeys the same approval gate as plain
  download — a pending bundle is refused.
- Recipient decrypts with the same passphrase (wrong-passphrase and tampered
  ciphertext are reported identically, giving no oracle).

### 6a. Sealed export (recipient public key, true E2E)

When there is no shared secret to establish, seal the bundle to the recipient's
**public key** instead — the appliance holds **no** decryption capability, so
only the recipient's private key can ever open it.

**UI:** Support panel → **Seal** on a ready bundle → enter a registered recipient
**name** (see below) or paste a raw base64 X25519 public key → the `.csb.sealed`
downloads.
**API:** `POST /api/support/bundles/{id}/download-sealed` (operator, body
`{"recipient_name":"<name>"}` **or** `{"recipient_public_key":"<base64 X25519>"}`).

- The bundle is wrapped in a NaCl anonymous sealed box (`CVRTSB01`: X25519 key
  agreement + XSalsa20-Poly1305). The operator supplies the recipient's public key
  (obtained out-of-band — e.g. TAC publishes it and you verify its fingerprint);
  the appliance never sees or stores a private key.
- Same approval gate as plain download — a pending bundle is refused.
- Anonymous boxes carry no sender identity by design; the bundle's **own** manifest
  hashes remain the integrity/authenticity anchor for the contents.

#### Recipient registry (register once, seal by name)

Pasting a raw key on every seal is error-prone, and an invalid (low-order) key
would silently defeat the guarantee, so register a recipient once and seal to it
by name thereafter.

**UI:** Support panel → **Sealing recipients** → enter a name + the recipient's
base64 public key → **Register** (admin). The card lists each recipient with its
**SHA-256 fingerprint** for out-of-band verification; **Rotate** replaces a
recipient's key in place (admin), **Remove** deletes one.
**API:** `GET /api/support/recipients` (viewer, list), `POST /api/support/recipients`
(admin, body `{"name","public_key"}`), `PUT /api/support/recipients/{name}` (admin,
body `{"public_key"}` — in-place key rotation), `DELETE /api/support/recipients/{name}`
(operator).

- **Key rotation** (`PUT`) keeps the name binding while swapping the key +
  fingerprint (re-validated with the low-order guard), so a rotated TAC key needs
  no delete/re-add and every reference to the name keeps working. Verify the **new**
  fingerprint out-of-band after rotating.

- The key is **validated on registration** with the same low-order-point guard the
  seal path uses, so the registry can never hold a key that would break the E2E
  guarantee. The stored key is re-validated again at seal time.
- A recipient's public key and fingerprint are **not secret** — they are listed
  openly; the fingerprint is the trust anchor you verify with TAC once.
- The registry is **node-local** operational state (`<dataDir>/support/recipients.json`):
  it is never included in export/import, config-version rollback, or CP→DP sync.

---

## 7. On-appliance diagnostics (`diagnose`)

Product-level, typed diagnostics — **never a shell**. Every verb is a fixed
in-binary operation with a typed, versioned JSON result; none take free-form OS
input or reach a host binary.

**UI:** Support panel → **Diagnostics** card. **API:** `POST /api/diagnose/<verb>`
(operator).

| Verb | What it checks | Network |
|---|---|---|
| `all` | one-shot aggregate of every no-input local verb (`storage` + `upstream` + `cluster` + `config`); overall ok = all pass. Excludes `dns`/`tls` (they need a target host) | none (in-memory + the storage probe) |
| `storage` | data-dir writability (real create+remove probe), free space, support-tree stat | none |
| `upstream` | upstream pool health + circuit state (from the existing health loop) | none (no new dial) |
| `cluster` | cluster/HA posture — role, fencing-lease validity/epoch, write authority, enrolled-node counts, standby sync health | none (in-memory state only) |
| `config` | live config-snapshot validity — the same cap validation that gates a CP→DP sync — plus non-secret collection sizes (policy rules, blocklist, categories, …); never the snapshot values | none (in-memory assembly) |
| `support` | support-bundle **store** health — bundle count, aggregate size, age spread, the retention bounds in force, and the janitor's last-sweep time + evicted total; counts + a timestamp only, never bundle content. Answers "why did a bundle disappear?" | none (reads bundle manifests) |
| `dns <host>` | bounded resolution of a bare hostname | resolves; **refuses** private/internal targets |
| `tls <host:port>` | bounded handshake + leaf identity + chain/expiry (no MITM) | connects; **refuses** private/internal targets; verification deferred then reported |

All `diagnose` verbs are bounded (timeouts), audited, and — for `dns`/`tls` —
SSRF-guarded: a target that resolves to a private/internal address is refused
(`blocked`) rather than probed, so a diagnostic can never be used to map internal
infrastructure from the proxy's network position.

---

## Where things live

- Bundles: `<dataDir>/support/bundles/<id>/` (`bundle.csb.tgz`, `manifest.json`,
  `redaction-report.json`, `state.json`).
- Capture-level state: `<dataDir>/support/debug_level.json` (never collected into a
  bundle).
- Audit trail: bundle create/approve/download/download_encrypted/delete and each
  `diagnose.<verb>` are recorded with the acting admin identity.
