# Certificates and CA lifecycle — the FE-6B.0 backend contract

This runbook describes how the inspection Root CA, the admin-UI certificate,
the upstream mTLS client certificate and the OCSP posture are read and changed
through the admin API after the FE-6B.0 backend-truth gate, and how a lost
response, a persistence fault or a restart is recovered. The React pages that
will consume this contract are FE-6B.1/6B.2; the legacy console already speaks
it.

Everything on this surface is **node-local**: nothing here is synced CP→DP
(only the cluster CA fingerprint travels in the ConfigSnapshot), nothing is on
the config-version rollback surface, and `GET /api/certificates` says so
(`scope: node-local`).

## 1. Identities and fences

| Object | Revision token | Read from | Echoed on |
|---|---|---|---|
| Root CA | `caRevision` = `car1:<sha256 hex of the live CA DER>` (`car1:none` without a CA) | `GET /api/ca/status`, `GET /api/certificates`, `GET /api/ca-cert` (JSON) | `?caRevision=` on the rotation challenge, the rotation confirm and a MITM import |
| Admin-UI certificate pair | `uiCertRevision` = `uic1:<sha256 hex of the persisted cert file>` (`uic1:none` when nothing is persisted) | `GET /api/certificates` (`uiCert.revision`), the dry run's `current` | `?uiCertRevision=` on a UI replace and a UI delete |
| OCSP desired posture | `ocspRevision` = `ocr1:<hex>` over the durable posture AND its generation (a toggle never returns to an earlier token) | `GET /api/ocsp`, `GET /api/certificates` | `?ocspRevision=` on `POST /api/ocsp` |

A fenced mutation without its token is `428 precondition_required` (the
current token under its own name in `current`); a moved token is `409 stale`
with the current one. The comparison happens **inside** the serialized
mutation boundary, never as a check followed by an unlocked write.

## 2. Operations, replay and the lookup

Every mutation — rotation, MITM import, UI replace, UI delete, OCSP set —
requires a client-generated UUID `?operationId=` (`428 operation_id_required`
without one). Before the first irreversible write the node records the intent
durably in `<dataDir>/certificate_operations.json` (256 slots; unresolved
intents are never evicted; a corrupt or unreadable file is fail-closed
`503 operation_ledger_degraded` with the file left in place as evidence).

- Re-sending the **same operationId with the same candidate** answers the
  recorded result with `replayed: true` — also after a restart — and mutates
  nothing.
- The same operationId with a **different action or candidate** is
  `409 operation_mismatch`.
- `GET /api/ca/operations/{operationId}` (admin) is the authoritative lookup:
  `pending`, `committed`, `aborted` or `outcome_unknown`. A pending intent is
  **settled by the lookup or at boot from the object's own evidence** — the
  live CA or the bundle on disk carrying the candidate fingerprint, the
  persisted UI certificate carrying the candidate digest, the durable OCSP
  posture at the intent's generation — never from a guess.
- The success audit (`ca.rotate`, `ca.import`, `cert.ui.replace`,
  `cert.ui.delete`, `ocsp.set`) is **operation-keyed and emitted exactly once
  after the durable terminal record**. A refused, aborted or ambiguous
  operation emits none. When the terminal record or the audit could not be
  made durable, the response says so (`recordState: pending_reconciliation`,
  `auditState: pending`) and the lookup completes it.

## 3. Root CA rotation (the bound challenge)

1. `GET /api/ca/status` → `revision`.
2. Generate a UUID `operationId`.
3. `POST /api/ca/rotate/challenge?operationId=…&caRevision=…` → `challenge`
   (64 hex), `fingerprint` of the CA being replaced, `expiresInSeconds` (120).
   The challenge is bound to the requesting actor, the operationId, the
   revision and the expiry, is single-use, and is consumed **only by a fully
   valid confirm**. Audited `ca.rotate_requested`.
4. `POST /api/ca/rotate?operationId=…&caRevision=…` with `{"challenge":"…"}`.
   Another actor, another operation, a moved revision, a wrong value or an
   expired challenge is `409 challenge_stale` with `current.changed` naming the
   bounded class(es) (`actor`, `operation`, `ca_revision`, `challenge`,
   `expired`) and the challenge is **not** consumed; a malformed body is
   `400 invalid_input`; no challenge is `428 challenge_required`.
5. **Persist before publish.** The new bundle is written atomically to the
   configured `-ca-path` first; only then is the candidate installed. A write
   failure is `500 persist_failed` (bounded `current.class`) with the current
   CA unchanged and the operation aborted. No bundle path configured is
   `503 persistence_not_configured`, refused before anything is minted.
6. The result carries `rotated: true`, `persisted: true`, `ca.revision` (the
   new fence), `previous.fingerprint`, `operationId`, `recordState`.

Auto-rotation (30 days before expiry, checked every 24 h) follows the same
rule: a bundle write failure leaves the current CA active, logs the class,
fires `cert_expiry`, and retries at the next check. Nothing is ever installed
unpersisted.

## 4. Importing a MITM CA and replacing the admin-UI certificate

`POST /api/certs/upload` (multipart `cert`, `key`, `target`):

- The **complete candidate is validated first** — `400 candidate_invalid` with
  a bounded `current.reason`: `malformed_pem`, `chain_invalid`,
  `key_mismatch`, `not_ca` (mitm), `unsupported_key` (the MITM signer needs an
  ECDSA key), `encrypted_key_unsupported`, `expired`, `not_yet_valid`. Nothing
  is written; no key material, parser text or path is echoed.
- `?dryRun=1` answers the candidate's public facts (`fingerprint`, `subject`,
  `isCA`, `keyAlgorithm`, `notBefore`/`notAfter`; for a UI pair also
  `dnsNames`, `chainLength`) plus the fence to echo — the T2 review material —
  without a fence, an operationId or a write.
- `target=mitm`: fenced on `caRevision`, persist-before-publish as in §3;
  the installed CA's own certificate is `409 candidate_duplicate`. Audited
  `ca.import`.
- `target=ui`: fenced on `uiCertRevision`; the pair is written atomically
  (cert then key, with a compensating rollback) under `<dataDir>/ui_tls_cert.pem`
  + `ui_tls_key.pem` (0600) and takes effect at the next restart
  (`activation: restart_required`). Audited `cert.ui.replace`.
- `DELETE /api/certs/ui?operationId=…&uiCertRevision=…` removes the pair (the
  private key first, so an interrupted delete never leaves a usable
  half-pair). `404 not_found` when nothing is persisted. The running listener
  keeps what it loaded at boot (`uiCert.active`, `activation`); the next restart
  falls back to the auto self-signed certificate. Audited `cert.ui.delete`.

Passphrases and private keys are write-only: never echoed, logged, audited or
recorded in the ledger.

## 5. OCSP posture

`GET /api/ocsp` (viewer) reports the DESIRED posture (`desired.enabled`,
`desired.source` ∈ default / yaml / admin), the RUNTIME posture, `durable`,
`revision`, `scope`, the counters, and — for the upstream mTLS client
certificate — `mtlsClientCertConfigured`, `mtlsClientCertLoaded` and, when not
loaded, a bounded `mtlsClientCertReason` (`cert_file_missing`,
`key_file_missing`, `load_failed`). The file path and the loader's text never
appear on this response.

`POST /api/ocsp?operationId=…&ocspRevision=…` `{"enabled": bool}` persists
the desired posture in `admin_settings.json` first and flips the checker only
after the write landed: a `200` (`durable: true`) survives a restart and wins
over `proxy.ocsp_check`; a persist failure is `500 persist_failed` with the
running posture unchanged. Audited `ocsp.set`.

## 6. Bounded classes, not raw errors

`GET /api/ca/status` and `GET /api/certificates` publish every fault as a
class — `unusableClass` (`expired`, `not_yet_valid`, `no_ca`),
`rotationPersistClass`, `loadFailureClass`, `loadRecoveryClass`
(`permission_denied`, `not_found`, `read_only`, `no_space`, `not_a_file`,
`io_error`, `write_failed`, `decrypt_failed`, `bundle_malformed`,
`load_failed`, `init_failed`, `expired`). The bundle path and the exact OS or
decrypt error stay in the process log. Every refusal on this surface is typed
JSON `{error, code[, current]}` with a closed `code` vocabulary; no route here
answers plain text.

## 7. Backup, restore, rollback, downgrade

See [`docker-compose-backup-restore.md` §13](docker-compose-backup-restore.md#13-certificates-the-ca-and-ocsp-in-a-backup):
the CA bundle is archived (Tier 1), the UI pair and the operation ledger are
not, the OCSP posture travels inside the sanitized settings file, none of them
is on the config-version rollback surface, and a pre-FE-6B.0 binary ignores
the new settings keys and the ledger.
