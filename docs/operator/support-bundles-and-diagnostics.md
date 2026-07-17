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

The bundle is written under `<dataDir>/support/bundles/<id>/` and its oldest
entries beyond the retention cap are evicted automatically.

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

---

## 7. On-appliance diagnostics (`diagnose`)

Product-level, typed diagnostics — **never a shell**. Every verb is a fixed
in-binary operation with a typed, versioned JSON result; none take free-form OS
input or reach a host binary.

**UI:** Support panel → **Diagnostics** card. **API:** `POST /api/diagnose/<verb>`
(operator).

| Verb | What it checks | Network |
|---|---|---|
| `storage` | data-dir writability (real create+remove probe), free space, support-tree stat | none |
| `upstream` | upstream pool health + circuit state (from the existing health loop) | none (no new dial) |
| `cluster` | cluster/HA posture — role, fencing-lease validity/epoch, write authority, enrolled-node counts, standby sync health | none (in-memory state only) |
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
